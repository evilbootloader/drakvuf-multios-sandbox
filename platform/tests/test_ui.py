"""The UI shell, and the one rule it exists to satisfy.

Issue #38 (DRAFT-045).

    Escape on output. Never sanitise on input.

The submitted filename must reach the guest byte-exact -- extension dispatch
and argv[0] self-checks are real evasion surface, which is why DRAFT-030
stopped naming the staged guest file after its hash. So the name arrives here
hostile by design, and the browser is where it is made safe.

`test_jobs_api.py` pins the input half: these names are ADMITTED at
submission. This file pins the output half. The two together are the contract.
"""

from __future__ import annotations

import uuid

import pytest
from markupsafe import escape

# Exactly the names test_jobs_api.py admits at submission. Duplicated as a
# literal rather than imported, deliberately: if someone narrows that list,
# this file should still assert the old names render safely rather than
# silently testing less.
HOSTILE = [
    '"; rm -rf ~ #',
    "$(whoami).sh",
    "`id`.bin",
    "'; DROP TABLE jobs; --",
    "<img src=x onerror=alert(1)>.exe",
    "a b c.exe",
    "<script>alert(1)",          # unclosed: no slash, so it survives the
    '"><script>alert(1)',        # sample-filename separator rule
    "<!--",
    "50%off.exe",
    "‮exe.txt",             # RTL override
]


def _job(conn, filename: str, *, state: str = "completed",
         target_os: str = "ubuntu") -> uuid.UUID:
    return conn.execute(
        """
        INSERT INTO jobs (target_os, submitted_filename, state, sha256,
                          size_bytes, detected_type)
        VALUES (%s, %s, %s, 'af9c4ea0', 19, 'ASCII text')
        RETURNING id
        """,
        (target_os, filename, state),
    ).fetchone()[0]


# --- the escaping rule -----------------------------------------------------

@pytest.mark.parametrize("name", HOSTILE)
def test_a_hostile_filename_renders_inert(client, conn, name):
    """The name appears, and appears as text.

    Two assertions, and the second is the one that matters. That the name is
    present proves we did not sanitise it away; that its markup is escaped
    proves the browser will not act on it.
    """
    job_id = _job(conn, name)

    page = client.get(f"/ui/jobs/{job_id}").text

    # markupsafe.escape is the oracle because it is literally what Jinja's
    # autoescape applies. Python's html.escape differs on quote entities
    # (`&#x27;` vs `&#39;`), so comparing against it would fail on names
    # containing quotes while the page was perfectly correct.
    assert str(escape(name)) in page, \
        "the name was altered or dropped -- output escaping must not sanitise"
    if "<" in name:
        assert name not in page, f"unescaped markup reached the page: {name!r}"
        assert "&lt;" in page


@pytest.mark.parametrize("name", HOSTILE)
def test_a_hostile_filename_renders_inert_in_the_history(client, conn, name):
    """Same rule on the list view. Both views render the name, so both are
    tested -- an escaping rule that holds on one page and not the other is
    the shape most such bugs actually take."""
    _job(conn, name)

    page = client.get("/ui/jobs").text

    if "<" in name:
        assert name not in page
        assert "&lt;" in page


def test_the_title_escapes_too(client, conn):
    """<title> is a separate escaping context and an easy one to miss."""
    job_id = _job(conn, "</title><script>alert(1)")

    page = client.get(f"/ui/jobs/{job_id}").text

    assert "</title><script>" not in page


def test_only_the_vendored_script_is_marked_safe():
    """The `| safe` count is the review surface.

    Server-rendering was chosen so escaping is structural: autoescape is on,
    so the dangerous thing is an explicit `| safe`. That only works while
    somebody counts them.
    """
    from pathlib import Path

    from sandbox_platform import ui

    root = Path(ui.__file__).parent / "templates"
    offenders = [
        (p.name, line)
        for p in root.rglob("*.html")
        for line in p.read_text().splitlines()
        if "| safe" in line or "|safe" in line
    ]
    assert offenders == [], offenders


# --- the tab shell is per-OS capability aware ------------------------------

def test_ubuntu_has_no_registry_tab(client, conn):
    """regmon is Windows-only, so a Registry tab on an Ubuntu job could never
    be filled. A fixed tab list would give Ubuntu a permanently empty tab,
    which reads as a broken page rather than a property of the guest."""
    job_id = _job(conn, "x.bin", target_os="ubuntu")

    page = client.get(f"/ui/jobs/{job_id}").text

    assert ">Registry<" not in page
    assert ">Behaviour<" in page


def test_windows_does_have_a_registry_tab(client, conn):
    job_id = _job(conn, "x.exe", target_os="windows")

    page = client.get(f"/ui/jobs/{job_id}").text

    assert ">Registry<" in page


def test_a_tab_that_cannot_apply_falls_back_rather_than_404s(client, conn):
    """A bookmarked Registry link on an Ubuntu job is a stale link, not an
    error."""
    job_id = _job(conn, "x.bin", target_os="ubuntu")

    r = client.get(f"/ui/jobs/{job_id}?tab=registry")

    assert r.status_code == 200


# --- the catalogue does not invent evidence --------------------------------

def test_windows_claims_nothing_is_proven(client):
    """Windows has no execution evidence in this project at all.

    The four default plugins are what the pipeline WOULD enable there, which
    is a plan and not a record. Labelling them 'proven' on the submit form
    would be inventing evidence -- the exact failure this project's
    Candidate/evidenced discipline exists to prevent.
    """
    page = client.get("/ui/plugins/windows").text

    assert "proven" not in page
    assert "candidate" in page


def test_ubuntu_and_android_claim_the_same_four(client):
    """Both are Linux-kernel guests and both are evidenced end to end."""
    for os_ in ("ubuntu", "android"):
        page = client.get(f"/ui/plugins/{os_}").text
        assert page.count("proven") == 4, os_
        # Windows-only plugins are named as unavailable rather than hidden:
        # "why is there no registry tab" deserves an answer on the page.
        assert "regmon" in page and "tlsmon" in page


def test_an_unknown_target_os_is_refused(client):
    """The same closed set as submission, not a second weaker boundary."""
    assert client.get("/ui/plugins/linux").status_code == 422

def test_a_tab_with_no_data_is_marked_as_such(client, conn):
    """#38 ships with most tabs empty on purpose.

    A tab you can only discover is empty by clicking reads as a fault, so the
    tab bar distinguishes them and the title names the issue that will fill
    it. Overview always has content; Behaviour does not, until DRAFT-050.
    """
    job_id = _job(conn, "x.bin")

    page = client.get(f"/ui/jobs/{job_id}").text

    behaviour = [ln for ln in page.splitlines() if ">Behaviour<" in ln][0]
    assert 'data-empty="1"' in behaviour or "data-empty" in page
    overview = [ln for ln in page.splitlines() if ">Overview<" in ln][0]
    assert "data-empty" not in overview


def test_the_history_hash_says_it_is_truncated(client, conn):
    """A silently-cut digest invites someone to compare a prefix against a
    full one and conclude they differ."""
    job_id = _job(conn, "x.bin")
    conn.execute("UPDATE jobs SET sha256 = %s WHERE id = %s", ("a" * 64, job_id))

    page = client.get("/ui/jobs").text

    assert "…" in page
    assert 'title="' + "a" * 64 + '"' in page


# --- searching by digest ---------------------------------------------------

HASH = "af9c4ea0d7be30203e00346c79d1bdf645568614ab6ced2610fa3dbef406e890"


def _hashed(conn, filename: str, sha: str) -> uuid.UUID:
    job_id = _job(conn, filename)
    conn.execute("UPDATE jobs SET sha256 = %s WHERE id = %s", (sha, job_id))
    return job_id


def test_a_full_digest_finds_its_job(client, conn):
    _hashed(conn, "wanted.bin", HASH)
    _hashed(conn, "other.bin", "b" * 64)

    page = client.get(f"/ui/jobs?q={HASH}").text

    assert "wanted.bin" in page
    assert "other.bin" not in page


@pytest.mark.parametrize("n", [1, 4, 8, 12, 32, 63])
def test_the_opening_characters_are_enough(client, conn, n):
    """Incremental: the results narrow as more of the digest is typed.

    Twelve is the length this history displays, so a digest copied off our own
    page must find its job -- a UI that showed a short form and then refused
    to search for it would be setting a trap.
    """
    _hashed(conn, "wanted.bin", HASH)
    _hashed(conn, "other.bin", "b" * 64)

    page = client.get(f"/ui/jobs?q={HASH[:n]}").text

    assert "wanted.bin" in page
    assert "other.bin" not in page


def test_the_middle_of_a_digest_does_not_match(client, conn):
    """Anchored at the start, deliberately, and this pins it.

    Nobody holds the middle of a hash: a tool gives you all 64 characters, a
    UI gives you the first few. Matching anywhere would serve a way of working
    that does not exist -- and it would be unindexable forever, since
    `LIKE '%abc%'` can never use a btree while `LIKE 'abc%'` can, once this
    table grows enough to want one.
    """
    _hashed(conn, "wanted.bin", HASH)

    page = client.get(f"/ui/jobs?q={HASH[20:28]}").text

    assert "wanted.bin" not in page
    assert "Nothing matches" in page


def test_a_malformed_digest_is_named_rather_than_silently_empty(client, conn):
    """"No results" for a bad digest is indistinguishable from "no such
    sample", and only one of those is worth acting on."""
    _hashed(conn, "wanted.bin", HASH)

    page = client.get("/ui/jobs?q=zzzz").text

    assert "is not a SHA-256" in page
    assert "wanted.bin" not in page


@pytest.mark.parametrize("attempt", ["%", "_", "%%", "a%", "af9c%", "' OR 1=1 --"])
def test_a_wildcard_cannot_be_typed_into_the_pattern(client, conn, attempt):
    """The `%` that makes this a substring search is added by the server.

    The field accepts hex only, so a user cannot smuggle one in and turn the
    query into a match-everything. The value is a bound parameter regardless,
    so this is belt over braces -- but a search that quietly returned the
    whole table would be a bug even without being a vulnerability.
    """
    _hashed(conn, "wanted.bin", HASH)
    _hashed(conn, "other.bin", "b" * 64)

    page = client.get("/ui/jobs", params={"q": attempt}).text

    assert "is not a SHA-256" in page
    assert "wanted.bin" not in page and "other.bin" not in page


def test_the_digest_is_case_insensitive(client, conn):
    """Tools emit both. sha256sum is lowercase, plenty of Windows tools and
    VirusTotal are not, and a search that failed on a pasted uppercase digest
    would look like the sample was missing."""
    _hashed(conn, "wanted.bin", HASH)

    assert "wanted.bin" in client.get(f"/ui/jobs?q={HASH.upper()}").text


def test_filters_combine(client, conn):
    a = _hashed(conn, "linux.bin", HASH)
    conn.execute("UPDATE jobs SET target_os = 'ubuntu' WHERE id = %s", (a,))
    b = _hashed(conn, "windows.exe", HASH)
    conn.execute("UPDATE jobs SET target_os = 'windows' WHERE id = %s", (b,))

    page = client.get(f"/ui/jobs?q={HASH}&target_os=windows").text

    assert "windows.exe" in page
    assert "linux.bin" not in page


def test_the_history_hash_links_to_a_search_for_it(client, conn):
    """"What else came from these bytes?" is the common next question, and
    DRAFT-030 makes it a real one: identical bytes under two names are
    deliberately two separate jobs."""
    _hashed(conn, "wanted.bin", HASH)

    page = client.get("/ui/jobs").text

    assert f'href="/ui/jobs?q={HASH}"' in page


# --- one sample, many analyses ---------------------------------------------

def test_a_hash_lists_every_analysis_of_those_bytes(client, conn):
    """DRAFT-030 makes this the normal case, not a duplicate.

    Identical bytes submitted under different names are deliberately separate
    jobs, because the submitted name is part of what is analysed -- extension
    dispatch and argv[0] self-checks are real evasion surface. Searching the
    digest must therefore return every run, and each must be openable.
    """
    ids = [_hashed(conn, name, HASH)
           for name in ("invoice.exe", "invoice.scr", "setup.exe")]
    _hashed(conn, "unrelated.bin", "b" * 64)

    page = client.get(f"/ui/jobs?q={HASH}").text

    for name in ("invoice.exe", "invoice.scr", "setup.exe"):
        assert name in page
    assert "unrelated.bin" not in page
    # Each row opens its own report.
    for job_id in ids:
        assert f'href="/ui/jobs/{job_id}"' in page


def test_several_analyses_of_one_sample_are_announced(client, conn):
    """Otherwise the reader sees rows with the same digest and reasonably
    wonders which is 'the' one. The answer is all of them."""
    for name in ("a.exe", "b.exe"):
        _hashed(conn, name, HASH)

    page = client.get(f"/ui/jobs?q={HASH}").text

    assert "2 analyses of these bytes" in page


def test_a_single_analysis_is_not_announced_as_several(client, conn):
    _hashed(conn, "only.exe", HASH)

    page = client.get(f"/ui/jobs?q={HASH}").text

    assert "analyses of these bytes" not in page


# --- paging ----------------------------------------------------------------

def _many(conn, n: int, sha: str = HASH) -> None:
    for i in range(n):
        _hashed(conn, f"sample-{i:03}.bin", sha)


def test_a_page_holds_thirty(client, conn):
    _many(conn, 70)

    page = client.get("/ui/jobs").text

    assert page.count('<td class="filename">') == 30
    assert "1–30 of 70" in page


def test_paging_walks_the_whole_set(client, conn):
    _many(conn, 70)

    seen = set()
    for n in (1, 2, 3):
        page = client.get(f"/ui/jobs?page={n}").text
        seen.update(m for m in (f"sample-{i:03}.bin" for i in range(70))
                    if m in page)
    assert len(seen) == 70


def test_the_last_page_is_short_and_says_so(client, conn):
    _many(conn, 70)

    page = client.get("/ui/jobs?page=3").text

    assert "61–70 of 70" in page
    assert page.count('<td class="filename">') == 10


def test_a_page_past_the_end_lands_on_the_last_one(client, conn):
    """Bookmark page 9, jobs age out, page 9 stops existing. An empty table
    there reads as data loss rather than as a stale link."""
    _many(conn, 70)

    page = client.get("/ui/jobs?page=99").text

    assert "61–70 of 70" in page
    assert page.count('<td class="filename">') == 10


def test_paging_keeps_the_filters(client, conn):
    """Landing on page 2 of everything after searching for a hash is a small
    betrayal that costs real confusion."""
    _many(conn, 40, sha=HASH)
    _many(conn, 40, sha="c" * 64)

    page = client.get(f"/ui/jobs?q={HASH}&page=2").text

    assert f"q={HASH}" in page          # carried into the page links
    assert "31–40 of 40" in page


def test_the_count_and_the_page_cannot_disagree(client, conn):
    """Both go through one filter builder. Two copies of that logic is how a
    list ends up claiming '412 results' while showing a different set."""
    _many(conn, 40, sha=HASH)
    _many(conn, 15, sha="c" * 64)

    page = client.get(f"/ui/jobs?q={HASH}").text

    assert "1–30 of 40" in page
    assert page.count('<td class="filename">') == 30


def test_the_bare_hostname_redirects_to_the_ui(client):
    """`/` is otherwise a 404 from a service that is working perfectly —
    cloudflared routes everything but `/analysis*` to the API, and the API has
    no root of its own."""
    r = client.get("/", follow_redirects=False)

    assert r.status_code == 302
    assert r.headers["location"] == "/ui"


def test_the_redirect_is_not_permanent(client):
    """308 would be cached hard and make `/` difficult to reclaim later — for
    a landing page, a public report index, or anything else."""
    assert client.get("/", follow_redirects=False).status_code not in (301, 308)


def test_healthz_is_not_swallowed_by_the_redirect(client):
    """The one deliberately unauthenticated endpoint, and the one a reverse
    proxy polls. A root route that shadowed it would be a quiet outage."""
    r = client.get("/healthz")

    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.parametrize("qs", [
    "state=&target_os=",              # what the form sends with both on "any"
    "q=&state=&target_os=",
    "state=&target_os=windows",
    "q=af9c&state=&target_os=",
])
def test_empty_filter_values_mean_unfiltered(client, conn, qs):
    """An HTML <select> whose "any" option has value="" submits `state=`.

    The parameter is PRESENT and empty, not omitted — so FastAPI tried to
    parse "" into the enum and the *unfiltered* search was the one case that
    returned 422. Reported from the deployment 2026-08-25.

    Missed by the earlier tests because they passed either a real value or
    nothing at all, never an empty string. They tested the API contract; this
    tests what a form actually sends.
    """
    _hashed(conn, "wanted.bin", HASH)

    r = client.get(f"/ui/jobs?{qs}")

    assert r.status_code == 200, r.text[:300]


def test_a_bad_filter_value_is_still_refused(client):
    """The closed set is untouched. Only the EMPTY value became permissive —
    `state=linux` is still a 422, which is issue #3's rule and the reason
    these are enums at all."""
    assert client.get("/ui/jobs?state=linux").status_code == 422
    assert client.get("/ui/jobs?target_os=freebsd").status_code == 422


# --- F9: the history list did not update ------------------------------------

def test_the_history_table_refreshes_while_a_job_can_still_change(client, conn):
    """Reported from the deployment 2026-08-26: `/ui/jobs` showed `queued`
    while the analysis had already finished.

    `job.js` is only loaded on a job's own page, so the detail view went live
    and the list it was reached from stayed frozen. Polled rather than pushed:
    the SSE channel is per job id, so a list would need a subscription per row
    or a new global stream, where one cheap query every few seconds is far less
    machinery for a page read at human speed.
    """
    conn.execute("INSERT INTO jobs (target_os, submitted_filename, state)"
                 " VALUES ('ubuntu', 'running.bin', 'executing')")

    body = client.get("/ui/jobs").text

    assert 'id="jobs-table"' in body
    assert 'data-live="1"' in body
    assert "/ui/jobs/table" in body


def test_a_page_of_finished_jobs_does_not_poll(client, conn):
    """What stops it polling forever. The server says whether anything on THIS
    page can still change and the htmx trigger reads it, so a history of
    completed work makes no requests at all."""
    conn.execute("INSERT INTO jobs (target_os, submitted_filename, state)"
                 " VALUES ('ubuntu', 'done.bin', 'completed')")

    assert 'data-live="0"' in client.get("/ui/jobs").text


def test_the_refresh_keeps_the_filters_and_the_page(client, conn):
    """A refresh that dropped the filter would show a different result set
    every five seconds; one that dropped the page would move the table under
    the reader."""
    # A row that MATCHES the filter. Without one the page renders its empty
    # state instead of the table, so there is no poll to inspect -- which is
    # correct behaviour and was the first version of this test's mistake.
    conn.execute("INSERT INTO jobs (target_os, submitted_filename, state)"
                 " VALUES ('ubuntu', 'filtered.bin', 'completed')")

    body = client.get("/ui/jobs",
                      params={"state": "completed", "target_os": "ubuntu",
                              "page": 1}).text

    # The hx-get attribute, wherever it wraps. Searched across the whole body
    # rather than line by line: the first version of this test split on
    # newlines and found nothing, because the attribute sits on its own line
    # inside a multi-line tag and the value is HTML-escaped (`&amp;`).
    poll = body[body.index("/ui/jobs/table"):][:200]
    assert "state=completed" in poll
    assert "target_os=ubuntu" in poll
    assert "page=" in poll


def test_the_table_fragment_renders_the_same_rows_as_the_page(client, conn):
    """One context builder for both, so the polled fragment cannot drift from
    the full page."""
    conn.execute("INSERT INTO jobs (target_os, submitted_filename, state)"
                 " VALUES ('ubuntu', 'both.bin', 'executing')")

    assert "both.bin" in client.get("/ui/jobs").text
    assert "both.bin" in client.get("/ui/jobs/table").text


def test_the_fragment_is_only_the_table(client, conn):
    """It replaces #jobs-table's contents, so anything outside the table --
    the filters, the pagination -- would be duplicated into the page."""
    fragment = client.get("/ui/jobs/table").text

    assert "<table" in fragment
    assert "<form" not in fragment
    assert 'id="jobs-table"' not in fragment


# --- F13: a cached stylesheet made a working console display nothing --------

def test_static_assets_carry_a_cache_key(client):
    """The console connected, received a full 1024x768 framebuffer, and drew
    nothing: noVNC scales its canvas from the CONTAINER's measured size, and
    `.console-screen` -- the rule that gives the container a height -- was in a
    stylesheet the browser had cached from before that rule existed.

    `getComputedStyle(el).minHeight` read `0px` against a rule saying `320px`,
    which is only possible if the rule is not in the CSSOM at all.

    A working relay that displays nothing is an expensive way to find a cache,
    so the assets carry a key that changes when they do.
    """
    body = client.get("/ui/submit").text

    assert "app.css?v=" in body
    assert "submit.js?v=" in body


def test_the_cache_key_is_the_same_across_requests(client):
    """Derived from file mtime, not per-process or per-request. A restart that
    changed nothing must not invalidate a cache, or the key is just
    cache-busting with extra steps."""
    a = client.get("/ui/submit").text
    b = client.get("/ui/jobs").text

    import re
    ka = re.search(r"app\.css\?v=(\d+)", a).group(1)
    kb = re.search(r"app\.css\?v=(\d+)", b).group(1)
    assert ka == kb


def test_the_cache_key_tracks_the_files(tmp_path, monkeypatch):
    """It has to CHANGE when an asset does, or it is decoration."""
    from sandbox_platform import ui

    (tmp_path / "a.css").write_text("x")
    monkeypatch.setattr(ui, "_HERE", tmp_path.parent)
    (tmp_path.parent / "static").mkdir(exist_ok=True)
    (tmp_path.parent / "static" / "a.css").write_text("x")
    first = ui._asset_version()

    import os, time
    later = time.time() + 120
    os.utime(tmp_path.parent / "static" / "a.css", (later, later))

    assert ui._asset_version() != first
