"""The operator-facing UI. Issue #38 (DRAFT-045, rescoped 2026-08-24).

**This is the shell, not the product.** Layout, theme, submission, history,
live status and a tab framework. Each tab's *content* is a separate issue with
its own evidence, so no tab renders data before the pipeline that produces it
exists -- which matters, because per `catalogue.py` several tabs have no
possible data source on Ubuntu or Android at all.

**Server-rendered, and that is a security decision rather than a taste one.**
Jinja autoescapes by default, so the escaping rule this UI has to satisfy
becomes structural: the dangerous thing is an explicit `| safe` that a
reviewer can grep for, not an absent escape call nobody notices.

The rule, which runs opposite to the instinct:

    Escape on output. Never sanitise on input.

The submitted filename must reach the guest byte-exact -- extension dispatch
and argv[0] self-checks are real evasion surface, which is why DRAFT-030
stopped naming the staged guest file after its hash. `test_jobs_api.py`
already pins `<script>alert(1)`, `"><script>alert(1)` and `<!--` as *admitted*
at submission. Those names are this UI's contract.

**These routes read. They never mutate.** Submission goes through the JSON API
from the browser, so there is one admission path rather than two, and this
router holds no logic that could disagree with it.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlencode
from uuid import UUID

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path as PathParam, Query
from pydantic import BeforeValidator
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from .. import auth, catalogue, egress, launch
from .. import jobs as dal
from .. import calls as calls_store
from .. import cape
from .. import screenshots as screenshot_store
from ..config import settings
from ..db import connection
from ..enums import CONSOLE_STATES, TERMINAL_STATES, EgressMode, JobState, TargetOs
from ..routers.jobs import _detail, count_jobs, query_jobs

_HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))
static = StaticFiles(directory=str(_HERE / "static"))


def _by_directory(artifacts: dict[str, str]) -> list[tuple[str, list[tuple[str, str]]]]:
    """Artifact names and links grouped by their first path segment, the
    top level ("") first and then each directory in name order -- the
    Artifacts tab's groups. Order within a group is the manifest's."""
    groups: dict[str, list[tuple[str, str]]] = {}
    for name, url in artifacts.items():
        head, sep, _ = name.partition("/")
        groups.setdefault(head if sep else "", []).append((name, url))
    return sorted(groups.items(), key=lambda kv: (kv[0] != "", kv[0]))


templates.env.filters["by_directory"] = _by_directory


def _asset_version() -> str:
    """A cache key that changes when the assets do, and not otherwise.

    Without one, a browser keeps serving the stylesheet it already has. That
    cost a live-console debugging session on 2026-08-26: the console connected
    and received a full 1024x768 framebuffer, and noVNC scaled its canvas to
    0x0 because `.console-screen` -- which sets the container's height -- was
    in a stylesheet the browser had cached from before the rule existed. The
    symptom was a working relay that displayed nothing.

    Newest mtime rather than a per-process value: a restart that changed
    nothing should not invalidate a cache, and an edit that changed something
    must. `novnc/` is skipped -- it is pinned and 57 files is a lot of stat
    calls for something that only changes on a deliberate upgrade.
    """
    newest = 0.0
    for path in (_HERE / "static").iterdir():
        if path.is_file():
            newest = max(newest, path.stat().st_mtime)
    return str(int(newest))


ASSET_VERSION = _asset_version()

# Same dependency as the JSON routes, attached to the ROUTER rather than to
# individual routes so a view added later cannot be public by omission.
#
# **`caller_identity`, not `access_identity`, since the cut-over.** The old gate
# was the Cloudflare verifier, which refuses outright when `REQUIRE_ACCESS_JWT`
# is set and no Access header is present -- so a caller holding a session this
# platform issued was turned away here, before `caller_identity` could look at
# their cookie. The session plumbing was real and unreachable. This gate accepts
# either credential and refuses only when NEITHER produces an identity.
router = APIRouter(prefix="/ui", tags=["ui"],
                   dependencies=[Depends(auth.caller_identity)])

# **A second router, because `dependencies=[]` on a route does not remove the
# router's.** That was the first attempt and it is simply not how FastAPI
# composes them: router-level dependencies always run, so `/ui/login` sat behind
# the very gate it exists to get someone through -- unreachable, with a comment
# above it claiming the opposite. Measured, not assumed.
#
# Nothing here may read a job or name a tenant. Rendering the sign-in page is
# not privileged: the form posts to `/api/v1/auth/login`, which is where
# credentials are actually checked.
public_router = APIRouter(prefix="/ui", tags=["ui"])


def _render(request: Request, template: str, **ctx) -> HTMLResponse:
    ctx.setdefault("asset_version", ASSET_VERSION)
    # **Whether the session is ours decides whether Sign out is offered.**
    # Read from the cookie here rather than taken as a dependency because
    # `/ui/login` is on the public router and must render for a caller with no
    # identity at all -- a dependency that refused would make the sign-in page
    # unreachable, which is the bug the public router exists to avoid.
    ctx.setdefault("own_session",
                   auth.session_is_ours(request.cookies.get("sandbox_access")))
    return templates.TemplateResponse(request, template, ctx)


@public_router.get("/login", response_class=HTMLResponse)
def login_view(request: Request) -> HTMLResponse:
    return _render(request, "login.html", view="login")


@router.get("/account", response_class=HTMLResponse)
def account_view(request: Request) -> HTMLResponse:
    """Manage the second factor. What it shows is decided by `account.js`,
    which asks the API rather than being told by this template -- so the page
    cannot disagree with the database about whether MFA is on."""
    return _render(request, "account.html", view="account")


@router.get("", response_class=HTMLResponse)
@router.get("/submit", response_class=HTMLResponse)
def submit_view(request: Request) -> HTMLResponse:
    first = next(iter(TargetOs))
    return _render(
        request, "submit.html",
        view="submit",
        target_oses=[o.value for o in TargetOs],
        os=first.value,
        plugins=catalogue.for_os(first),
        defaults=catalogue.defaults_for(first),
        budget=_budget(first),
        egress_offers=_egress_offers(),
        launch=_launch(first),
    )


def _launch(os_: TargetOs) -> dict:
    """The Execution fieldset's options for this guest (`_launch.html`).

    Paths are built with `settings.analysis_username` for display; the value
    the form sends is the location's key.
    """
    user = settings.analysis_username
    sep = launch.SEP[os_]
    return {
        "locations": [{"key": loc.key.value, "label": loc.label,
                       "path": loc.path(user)}
                      for loc in launch.locations_for(os_)],
        "sep": sep,
        "splits_arguments": launch.SPLITS_ARGUMENTS[os_],
        "cmd_special": " ".join(launch.CMD_SPECIAL),
        "max_subdir": launch.MAX_SUBDIR_BYTES,
        "max_arguments": launch.MAX_ARGUMENT_BYTES,
        "subdir_example": sep.join(("tools", "x64")),
        "arguments_example": ("/S --config C:\\setup.ini"
                              if not launch.SPLITS_ARGUMENTS[os_]
                              else "--verbose -o 'out file.txt'"),
    }


def _egress_offers() -> list[egress.Offer]:
    """The ways out a submitter may actually choose, from `worker_egress`.

    Read live rather than cached: an operator who unsets SANDBOXD_ALLOW_DIRECT
    and restarts sandboxd expects `direct` to be gone from the form on the next
    page load, not on the next deploy. The query is one small indexed table.

    `offline` is prepended and never comes from the database. On Dom0 it is the
    absence of a rule, so every host can always provide it -- and a form with no
    options at all, on a deployment with no analysis host registered, would
    leave a submitter unable even to ask for the safest thing.
    """
    offers = []
    
    with connection() as conn:
        for row in dal.offered_exits(conn):
            offers.append(egress.Offer(
                name=row["name"],
                mode=EgressMode(row["mode"]),
                country=row["country"],
                caveats=tuple(row["caveats"] or ()),
            ))
    return egress.sort_offers(offers)


def _budget(os_: TargetOs) -> dict:
    """Trace-budget defaults for this guest.

    `disable_sysret` defaults ON for Android only, for the reasons
    `catalogue.sysret_disabled_by_default` gives. Ubuntu had it on from
    2026-08-29 to 2026-10-23, until the Falco rules became a consumer of the
    return values it threw away.

    **No longer decorative.** `disable_sysret` and `timeout` are columns on
    the jobs table since migration 0011, ride `Lease`, and are overlaid onto
    the guest defaults by `stages._trace_options`. So these are the values a
    submitter who never opens the advanced disclosure actually sends, not a
    cosmetic echo of `guests.default_trace_options`.

    That makes any disagreement with `guests.default_trace_options`
    load-bearing rather than untidy. Two remain:

      `timeout`         120 is the measured default for Ubuntu, Windows and an
                        Android ELF, but NOT for an Android APK, which gets
                        150s there. The kind is read from the sample's bytes on
                        the worker and cannot be known while this form renders,
                        so Android gets the APK's 150, and an Android ELF
                        traces 30 seconds longer than its default. (Until
                        2026-11-02 every guest got 150: the condition tested
                        `TargetOs.ANDROID`, always true, instead of `os_`.)
      `disable_sysret`  unticked for Windows against True there, so a Windows
                        submitter who leaves the form alone turns the flag off
                        rather than inheriting the Candidate default.
    """
    return {
        "timeout": 150 if os_ is TargetOs.ANDROID else 120,
        "max_timeout": catalogue.MAX_TRACE_TIMEOUT,
        "linux": os_ is not TargetOs.WINDOWS,
        "disable_sysret": catalogue.sysret_disabled_by_default(os_),
    }


@router.get("/plugins/{target_os}", response_class=HTMLResponse)
def plugin_picker(request: Request,
                  target_os: TargetOs) -> HTMLResponse:
    """The advanced disclosure's body, swapped by htmx when the OS changes.

    `target_os` is parsed into the enum by FastAPI, so an unknown value is a
    422 before any handler code runs -- the same closed-set boundary issue #3
    established, not a second, weaker one.
    """
    return _render(request, "_plugins.html",
                   os=target_os.value,
                   plugins=catalogue.for_os(target_os),
                   defaults=catalogue.defaults_for(target_os),
                   budget=_budget(target_os),
                   # The Execution fieldset is per guest too; see _launch.html.
                   launch=_launch(target_os), oob=True)


_HEX = re.compile(r"\A[0-9a-f]{1,64}\Z")


def _blank_is_absent(v: object) -> object:
    """Treat an empty query value as an absent one.

    An HTML `<select>` whose "any" option has `value=""` submits `state=` --
    the parameter is PRESENT and empty, not omitted. FastAPI then tried to
    parse `""` into the enum, so the *unfiltered* search was the one case that
    returned 422. Reported from the deployment 2026-08-25.

    The closed-set check is untouched for every non-empty value: `state=linux`
    is still a 422, which is issue #3's rule and the reason these are enums at
    all.
    """
    return None if v == "" else v


# Query-only, and deliberately not applied to the JSON API. A client sending
# `state=` there has made a mistake worth being told about; a browser sending
# it is just how forms work.
BlankableState = Annotated[JobState | None, BeforeValidator(_blank_is_absent)]
BlankableOs = Annotated[TargetOs | None, BeforeValidator(_blank_is_absent)]


# 30 a page. Small enough that a page is scannable without scrolling, and it
# is the number the operator asked for.
PAGE = 30


def _jobs_context(q: str, state, target_os, page: int, identity) -> dict:
    """Everything the history view and its table fragment both need.

    One builder so the polled fragment cannot drift from the full page -- a
    filter honoured on first load and dropped on refresh would quietly show a
    different result set every five seconds. The tenancy scope rides along for
    the same reason: the poll must not be able to show a different set from the
    page it is refreshing.
    """
    term = q.strip().lower()
    bad = bool(term) and not _HEX.match(term)

    filters = {"state": state, "target_os": target_os,
               "sha256_prefix": term or None, "identity": identity}
    total = 0 if bad else count_jobs(**filters)
    pages = max(1, -(-total // PAGE))
    page = min(page, pages)
    rows = [] if bad else query_jobs(**filters, limit=PAGE,
                                     offset=(page - 1) * PAGE)

    digests = {j.sha256 for j in rows if j.sha256}
    one_sample = digests.pop() if len(digests) == 1 else None

    return {
        "q": q.strip(), "bad_query": bad, "one_sample": one_sample,
        "state": state, "target_os": target_os,
        "states": [s.value for s in JobState],
        "target_oses": [o.value for o in TargetOs],
        "jobs": rows, "page": page, "pages": pages, "total": total,
        "first": 0 if not total else (page - 1) * PAGE + 1,
        "last": min(page * PAGE, total),
        # A window rather than every page number: 400 pages of links is not
        # navigation.
        "window": [n for n in range(page - 2, page + 3) if 1 <= n <= pages],
        # Whether anything on THIS page can still change. The poll stops when
        # nothing can, so a page of finished jobs makes no requests at all.
        "live": any(j.state not in TERMINAL_STATES for j in rows),
        # TWO query strings, and they differ by one field on purpose.
        #
        # `querystring` carries the filters only: the pagination links append
        # their own `page=`, so including one here would put two in the URL.
        #
        # `query` carries the filters AND the page, because the poll has to
        # come back to the page being looked at. Refreshing page 3 into page 1
        # would move the table under the reader every five seconds.
        "querystring": urlencode(
            {k: v for k, v in (("q", q.strip()),
                               ("state", state.value if state else ""),
                               ("target_os", target_os.value if target_os else ""))
             if v}),
        "query": urlencode(
            {k: v for k, v in (("q", q.strip()),
                               ("state", state.value if state else ""),
                               ("target_os", target_os.value if target_os else ""),
                               ("page", str(page)))
             if v}),
    }


@router.get("/jobs/table", response_class=HTMLResponse)
def jobs_table(request: Request,
               q: str = Query("", max_length=64),
               state: BlankableState = None,
               target_os: BlankableOs = None,
               page: int = Query(1, ge=1),
               identity: auth.Identity = None) -> HTMLResponse:
    """Just the table, for the poll on the history page (F9).

    Takes the same query parameters as the full view and builds its context
    with the same function, so a refresh cannot show a different filter than
    the page was rendered with.
    """
    return _render(request, "_jobs_table.html",
                   **_jobs_context(q, state, target_os, page, identity))


@router.get("/jobs", response_class=HTMLResponse)
def jobs_view(request: Request,
              q: str = Query("", max_length=64),
              state: BlankableState = None,
              target_os: BlankableOs = None,
              page: int = Query(1, ge=1),
              identity: auth.Identity = None) -> HTMLResponse:
    """History, with a search over the sample digest.

    Matches from the START of the digest, which is the only partial form
    anyone actually has -- a tool gives you all 64 characters, this table
    gives you the first twelve. See query_jobs for why anchoring also keeps
    the search indexable.

    The term is validated as hex rather than passed through. Two reasons, and
    only the second is about safety: a digest that is not hex cannot match
    anything, so saying so beats returning an empty list; and restricting the
    alphabet means `%` and `_` can never reach the LIKE pattern as wildcards.
    The value is bound as a parameter regardless, so this is belt over braces.
    """
    return _render(request, "jobs.html", view="jobs",
                   **_jobs_context(q, state, target_os, page, identity))


# --- the job page ----------------------------------------------------------------
#
# Every tab is one column of sections, top to bottom, and everything that
# opens does so in place: directly below the row that opened it, with its own
# close button, moving nothing else and hiding nothing (operator, 2026-11-11).
# The fragments below are what those rows fetch; each is also a plain page
# without htmx, as a link's fallback.

_TAB_BODIES = {
    "overview": "tabs/_overview.html",
    "signatures": "tabs/_signatures.html",
    "behaviour": "tabs/_behaviour.html",
    "timeline": "tabs/_timeline.html",
    "summary": "tabs/_summary.html",
    "network": "tabs/_network.html",
    "dropped": "tabs/_dropped.html",
    "memory": "tabs/_memory.html",
    "static": "tabs/_static.html",
    "screenshots": "tabs/_screenshots.html",
    "artifacts": "tabs/_artifacts.html",
}

# Rows of a long list drawn before "show more": enough to scan, few enough
# that a sample touching ten thousand files does not send ten thousand rows.
LIST_PAGE = 100
TIMELINE_PAGE = 300


def _tab_body(slug: str) -> str:
    return _TAB_BODIES.get(slug, "tabs/_pending.html")


def _job_context(job_id: UUID, tab: str, identity) -> dict:
    with connection() as conn:
        job = _detail(conn, job_id, identity)
        key_prefix = _key_prefix(conn, job_id)

    # The CAPE report, when the run uploaded one: read once per request for
    # whichever tab is drawing, and for the tab bar's counts.
    loaded = cape.for_job(job.id, job.manifest, key_prefix, expired=job.artifacts_expired)

    tabs = catalogue.tabs_for(job.target_os)
    slugs = {t.slug for t in tabs}
    # An unknown or OS-inapplicable tab falls back rather than 404s: a
    # bookmarked tab from the old layout is a stale link, not an error.
    active = tab if tab in slugs else "overview"

    # The filmstrip only when it is the tab being drawn: it reads the index
    # from the store, and every other tab would pay for a strip nobody sees.
    strip = None
    if active == "screenshots":
        strip = screenshot_store.for_job(job.id, job.manifest, key_prefix,
                                         job.artifacts,
                                         expired=job.artifacts_expired)

    return {
        "job": job,
        # Where the sample was dropped, for Overview. Display only, from this
        # platform's username -- see `launch.drop_dir`.
        "drop_dir": launch.drop_dir(job.target_os, job.drop_location,
                                    job.drop_subdir,
                                    settings.analysis_username),
        "tabs": tabs,
        "active": active,
        "tab": next(t for t in tabs if t.slug == active),
        "body_template": _tab_body(active),
        "filled": _filled(job, loaded),
        # The report itself, or the sentence for why there is none. Both are
        # read by every tab template; `report` is None for a run from before
        # the CAPE chain, which shows Screenshots and Artifacts only.
        "report": loaded.report,
        "report_error": loaded.error,
        "list_page": LIST_PAGE,
        "timeline_page": TIMELINE_PAGE,
        "strip": strip,
        "frame_count": screenshot_store.count(job.artifacts),
        # Rendered into data-terminal for job.js, which must know when to stop
        # listening. Passed from here rather than written as a literal in the
        # JS: two definitions of "terminal" would be free to drift, and the
        # symptom is a finished job whose EventSource reconnects forever.
        "terminal_states": sorted(s.value for s in TERMINAL_STATES),
        # DRAFT-056, off by default. Passed to the template so the console
        # panel is absent rather than rendered-and-broken when the capability
        # is switched off.
        "console_enabled": settings.console_enabled,
        # The states in which a clone exists, and therefore the states in which
        # a console can exist; see `terminal_states` for why it is passed.
        "console_states": sorted(s.value for s in CONSOLE_STATES),
    }


def _key_prefix(conn, job_id: UUID) -> str:
    """Where this job's objects live. Read AFTER `_detail`, which has just
    enforced the tenancy scope and 404'd otherwise, so this needs no scope of
    its own. Not on JobDetail: that is the API's response model, and the
    prefix is a storage detail nothing outside this process should learn."""
    return conn.execute(
        "SELECT key_prefix FROM jobs WHERE id = %s", (job_id,)
    ).fetchone()[0]


def _filled(job, loaded: cape.Loaded) -> set[str]:
    """Tabs with something to show."""
    filled = {"overview"}
    if job.artifacts or job.manifest:
        filled.add("artifacts")
    if loaded.report is not None:
        filled |= loaded.report.filled_tabs()
    # The capture is network data whether or not the guest attributed any:
    # tcpdump runs on every trace, outside DRAKVUF, and the tab links to it.
    if "capture.pcap" in job.artifacts or "wireshark_key_file.txt" in job.artifacts:
        filled.add("network")
    # Frames, not the index: an index alone is a capture that took nothing.
    if screenshot_store.count(job.artifacts):
        filled.add("screenshots")
    return filled


@router.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_view(request: Request,
             job_id: UUID = PathParam(),
             tab: str = Query("overview"),
             identity: auth.Identity = None) -> HTMLResponse:
    return _render(request, "job.html", view="jobs",
                   **_job_context(job_id, tab, identity))


@router.get("/jobs/{job_id}/live", response_class=HTMLResponse)
def job_live(request: Request,
             job_id: UUID = PathParam(),
             tab: str = Query("overview"),
             identity: auth.Identity = None) -> HTMLResponse:
    """The job's live region, for job.js's SSE refresh. The same partial the
    full page includes, so there is one definition of what a job page shows."""
    ctx = _job_context(job_id, tab, identity)
    return _render(request, "_job_live.html", **ctx)


@router.get("/jobs/{job_id}/tabs", response_class=HTMLResponse)
def job_tabs(request: Request,
             job_id: UUID = PathParam(),
             tab: str = Query("overview"),
             identity: auth.Identity = None) -> HTMLResponse:
    """Just the tab bar and its body, for a tab click. Narrower than `/live`
    deliberately: that also carries the live console (DRAFT-056), and swapping
    it on a tab click would kill an open session. The nav is inside this
    fragment, which is what lets `aria-selected` move."""
    ctx = _job_context(job_id, tab, identity)
    return _render(request, "_job_tabs.html", **ctx)


def _report_for(job_id: UUID, identity):
    """The job, its key prefix and its report, or a 404. Tenancy first:
    `_detail` refuses a job the caller may not read before anything here
    touches the store."""
    with connection() as conn:
        job = _detail(conn, job_id, identity)
        key_prefix = _key_prefix(conn, job_id)
    loaded = cape.for_job(job.id, job.manifest, key_prefix, expired=job.artifacts_expired)
    if loaded.report is None:
        raise HTTPException(404, "this run has no CAPE report")
    return job, key_prefix, loaded.report


def _calls_for(job, key_prefix: str) -> calls_store.Available:
    return calls_store.for_job(job.id, job.manifest, key_prefix, expired=job.artifacts_expired)


@router.get("/jobs/{job_id}/process/{seqid}", response_class=HTMLResponse)
def process_view(request: Request,
                 job_id: UUID = PathParam(),
                 seqid: int = PathParam(ge=0, le=10_000_000),
                 identity: auth.Identity = None) -> HTMLResponse:
    """One of the sample's processes: the panel a tree node opens in place.
    Its facts, its calls per category, its own share of the report, and the
    first page of its calls, parsed. `seqid`, not PID: the report's own
    process identity, which a reused PID cannot confuse."""
    job, key_prefix, report = _report_for(job_id, identity)
    process = report.by_seqid.get(seqid)
    if process is None:
        raise HTTPException(404, "no such process among the sample's")
    available = _calls_for(job, key_prefix)
    summary = available.process(seqid)
    page = calls_store.page(available, seqid) if summary else None
    return _render(request, "tabs/_process.html", job=job, report=report, process=process,
                   seqid=seqid, activity=report.activity(process), calls=summary, page=page,
                   filters={}, list_page=LIST_PAGE)


@router.get("/jobs/{job_id}/process/{seqid}/calls", response_class=HTMLResponse)
def calls_view(request: Request,
               job_id: UUID = PathParam(),
               seqid: int = PathParam(ge=0, le=10_000_000),
               cursor: str = Query("", max_length=32, pattern=r"^(\d+\.\d+)?$"),
               category: str = Query("", max_length=64),
               api: str = Query("", max_length=256),
               tid: str = Query("", max_length=32),
               failed: bool = Query(False),
               part: str = Query("block", pattern=r"^(block|rows)$"),
               identity: auth.Identity = None) -> HTMLResponse:
    """A process's calls, filtered: the whole block (filter change) or the
    next rows (`part=rows`, which "more" appends in place of itself)."""
    job, key_prefix, report = _report_for(job_id, identity)
    if seqid not in report.by_seqid:
        raise HTTPException(404, "no such process among the sample's")
    available = _calls_for(job, key_prefix)
    summary = available.process(seqid)
    if summary is None:
        raise HTTPException(404, "no calls recorded for this process")
    filters = {k: v for k, v in (("category", category), ("api", api), ("tid", tid)) if v}
    if failed:
        filters["failed"] = "1"
    page = calls_store.page(available, seqid, cursor, category, api, tid, failed)
    template = "tabs/_calls_rows.html" if part == "rows" else "tabs/_calls.html"
    return _render(request, template, job=job, report=report, seqid=seqid, calls=summary,
                   page=page, filters=filters)


@router.get("/jobs/{job_id}/call", response_class=HTMLResponse)
def call_view(request: Request,
              job_id: UUID = PathParam(),
              cid: int = Query(ge=0, le=1 << 40),
              seqid: int | None = Query(None, ge=0, le=10_000_000),
              pid: int | None = Query(None, ge=0, le=1 << 31),
              identity: auth.Identity = None) -> HTMLResponse:
    """One call, whole, opened in place: under its row in a process's calls
    (by seqid), or under a signature's mark (by PID and cid, as mark_call
    names it)."""
    job, key_prefix, report = _report_for(job_id, identity)
    process = report.by_seqid.get(seqid) if seqid is not None else report.process_for(pid)
    if process is None or process.seqid is None:
        raise HTTPException(404, "no such process among the sample's")
    found = calls_store.call(_calls_for(job, key_prefix), process.seqid, cid)
    if found is None:
        raise HTTPException(404, "no such call")
    return _render(request, "tabs/_call.html", job=job, report=report, process=process, call=found)


@router.get("/jobs/{job_id}/signature/{index}", response_class=HTMLResponse)
def signature_view(request: Request,
                   job_id: UUID = PathParam(),
                   index: int = PathParam(ge=0, le=100_000),
                   identity: auth.Identity = None) -> HTMLResponse:
    """What a signature matched, classified: opened in place under its row."""
    job, _, report = _report_for(job_id, identity)
    if index >= len(report.signatures):
        raise HTTPException(404, "no such signature")
    signature = report.signatures[index]
    return _render(request, "tabs/_signature_data.html", job=job, report=report,
                   signature=signature, index=index, marks=report.signature_marks(signature))


@router.get("/jobs/{job_id}/timeline", response_class=HTMLResponse)
def timeline_view(request: Request,
                  job_id: UUID = PathParam(),
                  object: str = Query("", max_length=32),
                  seqid: int | None = Query(None, ge=0, le=10_000_000),
                  offset: int = Query(0, ge=0, le=1 << 30),
                  part: str = Query("block", pattern=r"^(block|rows)$"),
                  identity: auth.Identity = None) -> HTMLResponse:
    """The timeline, filtered by object kind and process: the block (filter
    change) or the next rows (`part=rows`)."""
    job, _, report = _report_for(job_id, identity)
    template = "tabs/_timeline_rows.html" if part == "rows" else "tabs/_timeline_block.html"
    return _render(request, template, job=job, report=report,
                   **_timeline(report, object, seqid, offset))


def _timeline(report: cape.Report, object_: str, seqid: int | None, offset: int) -> dict:
    events = [e for e in report.events
              if (not object_ or e.object == object_) and (seqid is None or e.seqid == seqid)]
    return {"events": events[offset:offset + TIMELINE_PAGE], "matching": len(events),
            "offset": offset, "next_offset": offset + TIMELINE_PAGE
            if offset + TIMELINE_PAGE < len(events) else None,
            "filters": {k: v for k, v in (("object", object_), ("seqid", seqid)) if v not in ("", None)}}


templates.env.globals["timeline"] = _timeline


# The summary's lists, and the other lists a tab draws a page of.
_LISTS = cape.SUMMARY_KEYS


@router.get("/jobs/{job_id}/list/{name}", response_class=HTMLResponse)
def list_view(request: Request,
              job_id: UUID = PathParam(),
              name: str = PathParam(max_length=32),
              offset: int = Query(0, ge=0, le=1 << 30),
              seqid: int | None = Query(None, ge=0, le=10_000_000),
              identity: auth.Identity = None) -> HTMLResponse:
    """The rest of one of the summary's lists, after its first page: one
    process's (`seqid`), or the whole sample's for a report from before the
    per-process lists."""
    job, _, report = _report_for(job_id, identity)
    if name not in _LISTS:
        raise HTTPException(404, "no such list")
    if seqid is not None:
        if report.summary_by_process is None or seqid not in report.summary_by_process:
            raise HTTPException(404, "no such process among the sample's")
        items = report.summary_by_process[seqid].get(name, [])
    else:
        items = report.summary.get(name, [])
    return _render(request, "tabs/_list_rows.html", job=job, report=report, name=name, seqid=seqid,
                   items=items[offset:offset + LIST_PAGE], offset=offset,
                   next_offset=offset + LIST_PAGE if offset + LIST_PAGE < len(items) else None,
                   total=len(items))


# --- template helpers -------------------------------------------------------------

def _hexdump(text: str, width: int = 16, limit: int = 4096) -> list[tuple[str, str, str]]:
    """A buffer as (offset, hex, text) lines. The parser decoded DRAKVUF's
    \\xHH escapes to one character per byte; a character past 0xFF (a value
    that was never bytes) shows as `?`."""
    data = bytes(ord(c) if ord(c) < 256 else 0x3F for c in (text or "")[:limit])
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        out.append((f"{i:04x}", " ".join(f"{b:02x}" for b in chunk),
                    "".join(chr(b) if 0x20 <= b < 0x7F else "·" for b in chunk)))
    return out


def _size(n) -> str:
    try:
        n = int(n, 0) if isinstance(n, str) else int(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _secs(value) -> str:
    """Seconds into the trace as `12.345 s`, or an en dash when unknown."""
    if value is None:
        return "–"
    return f"{value:,.3f} s"


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _printable(text, oneline: bool = True) -> str:
    """A value with its control characters as `\\xHH`, as DRAKVUF printed
    them before the parser decoded them: a NUL or an escape sequence in a
    buffer must reach the page as something a reader can see, not as a
    character the browser drops or a terminal interprets. One line: newlines
    and tabs too."""
    text = "" if text is None else str(text)
    if oneline:
        text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group(0)):02x}", text)


templates.env.filters["printable"] = _printable
templates.env.filters["hexdump"] = _hexdump
templates.env.filters["size"] = _size
templates.env.filters["secs"] = _secs
templates.env.globals["is_autostart"] = cape.is_autostart
templates.env.tests["is_autostart"] = cape.is_autostart
templates.env.globals["port_name"] = lambda port: PORT_NAMES.get(port, "")

# A label beside a remote port, as CAPE's UI shows one. A hint for the eye,
# not a classification: 443 says nothing about what went over it.
PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 123: "ntp", 135: "rpc", 137: "netbios", 139: "smb",
    143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-alt", 8443: "https-alt",
}
