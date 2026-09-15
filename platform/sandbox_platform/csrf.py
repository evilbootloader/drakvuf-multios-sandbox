"""The header that proves a mutation came from this application's own pages.

DRAFT-061 decision 3, widened past `/auth` by review finding M-7.

**A header's PRESENCE is the whole defence, and it is complete.** A cross-site
HTML form cannot set a request header, and a cross-site `fetch` that tries
triggers a preflight -- which fails, because this app mounts no CORSMiddleware.
DRAFT-061 records that absence as what holds CSRF today, and this keeps that
property rather than trading it for a token, a session table, or a second
cookie.

The value is never checked, only the presence. There is nothing an attacker
could put in it that helps them, because they cannot set it at all.

**Why this is a module rather than a function in `routers/auth.py`.** It lived
there, attached to that one router, while every other mutating route relied on
`SameSite=Lax` for our own session and on Cloudflare's cookie policy for the
Access assertion -- a policy that is not ours to set. Two of the browser's own
calls were CORS-*simple* requests that a cross-site page could therefore issue:
`submit.js` sent `POST /uploaded` with no `Content-Type` at all, and
`balance.js` sent only `Accept`. `job.js` had the property and said so in a
comment calling its JSON content type "the whole of what makes this route
unreachable from another origin" -- correct for that call, and exactly the kind
of per-call reasoning that does not survive the next person adding a route.

So the rule moved somewhere every router can import it from, and the comment
explaining it lives with the rule instead of in one caller.

**It does NOT cover WebSockets**, and nothing here can. A handshake takes no
preflight and the browser's WebSocket API sets no headers, so the console's
browser end is guarded by an `Origin` check instead -- see
`routers/console.py::_origin_permitted`. Two mechanisms because the transport
forces it, not because one of them is weak.

**It does NOT cover the worker channel**, deliberately. `/api/v1/worker/*` is
authenticated by a bearer token that `sandboxd` sets explicitly on every
request; there is no ambient credential for a browser to attach, so there is no
CSRF to prevent. Requiring the header there would break Dom0 for no gain.
"""

from __future__ import annotations

from fastapi import Header, HTTPException, Request, status

#: Named for what it asserts rather than for the mechanism, so a reader meeting
#: it in a browser's network tab can tell what it is for.
CSRF_HEADER = "X-Sandbox-Request"

#: Methods that cannot change state, and therefore need no proof of origin.
#:
#: **This is what lets the dependency be attached to a whole router.** The jobs
#: router serves `GET /{job_id}/artifacts.zip` and `GET /{job_id}/artifact.zip`,
#: and `routers/jobs.py::_detail` hands those URLs to the browser as ordinary
#: links in `JobDetail.artifacts`. A person clicking a download link cannot set
#: a header, so an unconditional requirement would refuse every artifact
#: download -- while looking, from the code, exactly like tightening security.
#:
#: HEAD and OPTIONS are here for completeness rather than because anything
#: serves them; a route added later that does should not have to think about it.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def require_csrf_header(
    request: Request,
    x_sandbox_request: str | None = Header(default=None),
) -> None:
    """Refuse an unsafe request that did not come from our own pages.

    Attach to a ROUTER rather than to routes, so a route added later cannot
    forget it -- which is the same argument `routers/worker.py` makes for
    attaching its token dependency to the router, and the reason the
    method test lives in here rather than in each caller's decorator.
    """
    if request.method in _SAFE_METHODS:
        return
    if not x_sandbox_request:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"{CSRF_HEADER} header required",
        )