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

from .. import auth, catalogue, egress
from .. import jobs as dal
from ..config import settings
from ..db import connection
from ..enums import RUNNING_STATES, TERMINAL_STATES, EgressMode, JobState, TargetOs
from ..routers.jobs import _detail, count_jobs, query_jobs

_HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))
static = StaticFiles(directory=str(_HERE / "static"))


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
        budget=_budget(first),
        egress_offers=_egress_offers(),
    )


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

    `disable_sysret` defaults ON for both Linux guests, for different reasons.
    On Android it is not optional: an idle BlissOS clone emits thousands of
    binder ioctls and Looper polls before anything is analysed, and without it
    an APK could not finish drawing inside the trace window. Ubuntu adopted it
    on 2026-08-29 for throughput -- 2.06x, 415 -> 856 syscalls/s -- accepting
    that syscall return values are lost. See `guests.default_trace_options`
    for the full trade and the condition it rests on.

    **KNOWN GAP: this checkbox is decorative.** `disable_sysret` is not on the
    jobs table, not in `jobs.py`, and not on `sandboxd.api.Lease`, so a
    per-job tick or untick never reaches Dom0 in either direction --
    `sandboxd/stages.py:339` takes the flag from `guests.default_trace_options`
    and moves only the plugin list. Keeping this default aligned with that
    function is therefore cosmetic honesty, not wiring; the wiring is its own
    change.
    """
    return {
        "timeout": 180,
        "linux": os_ is not TargetOs.WINDOWS,
        "disable_sysret": os_ is not TargetOs.WINDOWS,
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
                   budget=_budget(target_os))


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


def _tab_body(slug: str) -> str:
    return {
        "overview": "tabs/_overview.html",
        "artifacts": "tabs/_artifacts.html",
    }.get(slug, "tabs/_pending.html")


def _job_context(job_id: UUID, tab: str, identity) -> dict:
    with connection() as conn:
        job = _detail(conn, job_id, identity)

    tabs = catalogue.tabs_for(job.target_os)
    slugs = {t.slug for t in tabs}
    # An unknown or OS-inapplicable tab falls back rather than 404s: a
    # bookmarked Registry tab on an Ubuntu job is a stale link, not an error.
    active = tab if tab in slugs else "overview"

    return {
        "job": job,
        "tabs": tabs,
        "active": active,
        "tab": next(t for t in tabs if t.slug == active),
        "body_template": _tab_body(active),
        # Which tabs actually hold something. Rendered in the tab bar so a
        # scaffold is legible AS a scaffold: an empty tab you only discover by
        # clicking reads as a broken page, and #38 ships with most of them
        # empty by design.
        "filled": _filled(job),
        # Placeholder until DRAFT-052 records the real selection on the job.
        "plugins": catalogue.defaults(job.target_os),
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
        # a console can exist. Passed from here rather than written as a
        # literal in the template, for the same reason `terminal_states` is:
        # two definitions of the window would be free to drift, and the symptom
        # is a panel offering a session the API then refuses.
        "console_states": sorted(s.value for s in RUNNING_STATES),
    }


def _filled(job) -> set[str]:
    """Tabs with content today. Everything else is waiting on its own issue."""
    filled = {"overview"}
    if job.artifacts or job.manifest:
        filled.add("artifacts")
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
    """The job's live region, for htmx tab clicks and job.js's SSE refresh.

    Renders the same partial the full page includes, so there is one
    definition of what a job page shows rather than one per entry point.

    **Replaced `/jobs/<id>/tab/<slug>`, which returned only the tab body.**
    That was too small a unit twice over: the tab bar is a sibling of the
    body, so swapping the body alone could never move `aria-selected` -- the
    underline stayed on whichever tab the server first rendered -- and an SSE
    refresh needs the state block and the tab bar, not just the body.
    """
    ctx = _job_context(job_id, tab, identity)
    return _render(request, "_job_live.html", **ctx)


@router.get("/jobs/{job_id}/tabs", response_class=HTMLResponse)
def job_tabs(request: Request,
             job_id: UUID = PathParam(),
             tab: str = Query("overview"),
             identity: auth.Identity = None) -> HTMLResponse:
    """Just the tab bar and its body, for a tab click.

    Narrower than `/live` deliberately. `/live` also carries the live console
    (DRAFT-056), and swapping that on a tab click would destroy the console
    element -- killing the WebSocket and the canvas mid-session, which is the
    fault putting the console above the tabs was supposed to avoid.

    The nav is INSIDE this fragment, which is what lets `aria-selected` move:
    swapping only the tab body left the underline wherever the server first
    put it.
    """
    ctx = _job_context(job_id, tab, identity)
    return _render(request, "_job_tabs.html", **ctx)
