"""The real ASGI app with one dependency overridden, for the browser tests.

`test_ui_browser.py` runs a real uvicorn in a subprocess, because TestClient is
not something Chromium can load. That puts it outside the `client` fixture's
identity override, so every submission arrives with `access_identity` returning
None -- which since migration 0008 is a 403 from `auth.required_identity`,
because `jobs.owner` is NOT NULL and there is nobody to record.

The alternative would be a real Access token, and a browser cannot mint one:
`Cf-Access-Jwt-Assertion` is added by Cloudflare's edge, and forging a
verifiable one here would mean teaching the subprocess to trust a test key.

So this module exists instead, and lives in `tests/` deliberately. Nothing in
`sandbox_platform/` knows it is here, and no environment variable switches
authentication off in a deployment -- the override is applied by a file the
service never imports.

Kept in step with `conftest.client` by hand; they are three lines apart and
one identity string. If they drift, the browser tests submit as somebody the
in-process tests never see, which is confusing rather than dangerous.
"""

from __future__ import annotations

from sandbox_platform import auth
from sandbox_platform.app import app

app.dependency_overrides[auth.access_identity] = (
    lambda: "fixture-owner@example.test"
)