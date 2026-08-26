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

from .. import auth, catalogue
from ..config import settings
from ..db import connection
from ..enums import TERMINAL_STATES, JobState, TargetOs
from ..routers.jobs import _detail, count_jobs, query_jobs

_HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))
static = StaticFiles(directory=str(_HERE / "static"))

# Same dependency as the JSON routes, attached to the ROUTER rather than to
# individual routes so a view added later cannot be public by omission.
router = APIRouter(prefix="/ui", tags=["ui"],
                   dependencies=[Depends(auth.access_identity)])


def _render(request: Request, template: str, **ctx) -> HTMLResponse:
    return templates.TemplateResponse(request, template, ctx)


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
    )


def _budget(os_: TargetOs) -> dict:
    """Trace-budget defaults for this guest.

    `disable_sysret` defaults ON for Android because it is not optional there:
    an idle BlissOS clone emits thousands of binder ioctls and Looper polls
    before anything is analysed, and without it an APK could not finish
    drawing inside the trace window. Ubuntu is deliberately left alone -- it is
    evidenced working and does not have the problem this solves.
    """
    return {
        "timeout": 180,
        "linux": os_ is not TargetOs.WINDOWS,
        "disable_sysret": os_ is TargetOs.ANDROID,
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


@router.get("/jobs", response_class=HTMLResponse)
def jobs_view(request: Request,
              q: str = Query("", max_length=64),
              state: BlankableState = None,
              target_os: BlankableOs = None,
              page: int = Query(1, ge=1)) -> HTMLResponse:
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
    term = q.strip().lower()
    bad = bool(term) and not _HEX.match(term)

    filters = {"state": state, "target_os": target_os,
               "sha256_prefix": term or None}
    total = 0 if bad else count_jobs(**filters)
    pages = max(1, -(-total // PAGE))          # ceiling division
    # A page past the end shows the last one rather than an empty table. That
    # happens for real: bookmark page 9, jobs age out, page 9 stops existing.
    page = min(page, pages)

    rows = [] if bad else query_jobs(
        **filters, limit=PAGE, offset=(page - 1) * PAGE)

    # When every row on this page is the same bytes, say so. DRAFT-030 makes
    # that a normal situation rather than a curiosity: identical bytes
    # submitted under different names are deliberately separate jobs, because
    # the name is part of what is being analysed. Without this the reader sees
    # several rows with the same digest and reasonably wonders which is "the"
    # one -- the answer is all of them, and they differ in the columns shown.
    digests = {j.sha256 for j in rows if j.sha256}
    one_sample = digests.pop() if len(digests) == 1 else None

    return _render(
        request, "jobs.html", view="jobs",
        q=q.strip(), bad_query=bad,
        one_sample=one_sample,
        state=state, target_os=target_os,
        states=[s.value for s in JobState],
        target_oses=[o.value for o in TargetOs],
        jobs=rows,
        page=page, pages=pages, total=total,
        first=0 if not total else (page - 1) * PAGE + 1,
        last=min(page * PAGE, total),
        # A window rather than every page number: 400 pages of links is not
        # navigation, it is wallpaper.
        window=[n for n in range(page - 2, page + 3) if 1 <= n <= pages],
        # Carried into every page link so paging does not silently drop the
        # filters -- landing on page 2 of everything after searching for a
        # hash is a small betrayal that costs real confusion.
        querystring=urlencode(
            {k: v for k, v in (("q", q.strip()),
                               ("state", state.value if state else ""),
                               ("target_os", target_os.value if target_os else ""))
             if v}),
    )


def _tab_body(slug: str) -> str:
    return {
        "overview": "tabs/_overview.html",
        "artifacts": "tabs/_artifacts.html",
    }.get(slug, "tabs/_pending.html")


def _job_context(job_id: UUID, tab: str) -> dict:
    with connection() as conn:
        job = _detail(conn, job_id)

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
             tab: str = Query("overview")) -> HTMLResponse:
    return _render(request, "job.html", view="jobs",
                   **_job_context(job_id, tab))


@router.get("/jobs/{job_id}/live", response_class=HTMLResponse)
def job_live(request: Request,
             job_id: UUID = PathParam(),
             tab: str = Query("overview")) -> HTMLResponse:
    """The job's live region, for htmx tab clicks and job.js's SSE refresh.

    Renders the same partial the full page includes, so there is one
    definition of what a job page shows rather than one per entry point.

    **Replaced `/jobs/<id>/tab/<slug>`, which returned only the tab body.**
    That was too small a unit twice over: the tab bar is a sibling of the
    body, so swapping the body alone could never move `aria-selected` -- the
    underline stayed on whichever tab the server first rendered -- and an SSE
    refresh needs the state block and the tab bar, not just the body.
    """
    ctx = _job_context(job_id, tab)
    return _render(request, "_job_live.html", **ctx)


@router.get("/jobs/{job_id}/tabs", response_class=HTMLResponse)
def job_tabs(request: Request,
             job_id: UUID = PathParam(),
             tab: str = Query("overview")) -> HTMLResponse:
    """Just the tab bar and its body, for a tab click.

    Narrower than `/live` deliberately. `/live` also carries the live console
    (DRAFT-056), and swapping that on a tab click would destroy the console
    element -- killing the WebSocket and the canvas mid-session, which is the
    fault putting the console above the tabs was supposed to avoid.

    The nav is INSIDE this fragment, which is what lets `aria-selected` move:
    swapping only the tab body left the underline wherever the server first
    put it.
    """
    ctx = _job_context(job_id, tab)
    return _render(request, "_job_tabs.html", **ctx)
