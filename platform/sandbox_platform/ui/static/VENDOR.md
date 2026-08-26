# Vendored front-end code

**One file, and it is the only third-party front-end code in this project.**
Recorded here because a malware-analysis platform is a poor place to acquire
supply-chain dependencies casually, and "we added a script tag" is exactly the
kind of change that leaves no trace anyone reviews later.

| | |
|---|---|
| File | `htmx.min.js` |
| Version | **2.0.4**, pinned |
| Source | `https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js` |
| SHA-256 | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |
| Size | 50,917 bytes |
| Retrieved | 2026-08-25 |
| Licence | 0BSD |

Verify before trusting a copy:

```sh
sha256sum platform/sandbox_platform/ui/static/htmx.min.js
# e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447
```

## Why vendored rather than fetched from a CDN

A strict CSP blocks external hosts, so a CDN reference would not load at all.
Beyond that, a page fronting a malware store should not make requests to
third-party infrastructure on every view — the request itself is a signal
about what is being looked at and when.

## Why htmx rather than a framework, or nothing

It buys three behaviours and no build step: swapping the plugin picker when
the target OS changes, swapping a job's live region on a tab click, and — via
`htmx.ajax` from `job.js` — swapping that same region when a server-sent event
says the job moved. That is the whole of it.

The third is why `job.js` calls `htmx.ajax` rather than doing its own fetch:
the swap has to re-process the new nodes, and hand-rolling that is how the tab
bar ends up inert after the first update.

The alternative considered was **no dependency at all** — both behaviours are
a `fetch` and an `innerHTML` assignment, roughly twenty lines, and this
project already hand-rolls `submit.js`. That would make the "no third-party
front-end code" property absolute rather than nearly so.

It was not taken because the swap target is server-rendered HTML, and hand-
rolled `innerHTML` assignment is precisely where an escaping rule gets lost:
`submit.js` uses `textContent` throughout for that reason, and a bespoke
swapper would have to reintroduce `innerHTML` in the one place this UI renders
untrusted data. htmx does that swap in code that is reviewed by many more
people than this repository has.

`submit.js` remains hand-written because the submission sequence — reserve,
upload to the object store, admit — is not a declarative swap and would need
custom code under any framework. `job.js` is hand-written for the same reason
and stays deliberately small: it owns the EventSource lifecycle and nothing
else, delegating every DOM change to htmx.

## Upgrading

Change the version, re-download, update the hash above, and re-run
`tests/test_ui_browser.py` — the browser tests are what would actually catch a
regression in the swap behaviour.
---

# noVNC — the live console client

| | |
|---|---|
| Files | `novnc/core/`, `novnc/vendor/` (57 files) |
| Version | **1.6.0**, pinned |
| Source | `https://github.com/novnc/noVNC/archive/refs/tags/v1.6.0.tar.gz` |
| Tarball SHA-256 | `5066103959ef4e9b10f37e5a148627360dd8414e4cf8a7db92bdbd022e728aaa` |
| Size | 752 KB on disk |
| Retrieved | 2026-08-26 |
| Licence | MPL-2.0 (`novnc/LICENSE.txt`) |

Verify before trusting a copy:

```sh
curl -sSL https://github.com/novnc/noVNC/archive/refs/tags/v1.6.0.tar.gz | sha256sum
# 5066103959ef4e9b10f37e5a148627360dd8414e4cf8a7db92bdbd022e728aaa
```

## Why a second vendored dependency, when the first one was argued over

DRAFT-056 states the cost plainly: *"noVNC is a few hundred KB against htmx's
50, and a second entry in `ui/static/VENDOR.md`. Worth it — the alternative is
writing an RFB protocol client."*

That is the whole argument. RFB has a version negotiation, a security
handshake, and a dozen framebuffer encodings — Raw, CopyRect, RRE, Hextile,
Tight, ZRLE — each with its own decoder. Implementing that is not a feature,
it is a project.

**Only `core/` and `vendor/`.** The upstream `app/` directory is noVNC's own
full-page viewer, with its own UI, settings panel, clipboard and file-transfer
controls. None of that is wanted: DRAFT-056 puts clipboard, file transfer and
audio out of scope, each being *"a separate channel into a malware VM and none
is needed to click a button"*. Taking `core/` alone means those controls do not
exist to be enabled by accident.

`vendor/` is required by `core/` — it holds the `pako` inflate used by the
Tight and ZRLE decoders. It is a dependency of the decoders, not a second
choice we made.

## ES modules, so still no build step

`core/rfb.js` is an ES module and is loaded with `<script type="module">`. That
keeps the property the htmx entry above argues for: nothing here is compiled,
bundled or minified by us, so what is served is what was downloaded and the
hash above is checkable against the running deployment.

## What connects it to the platform

`RFB` is pointed at `wss://<host>/api/v1/jobs/<id>/console`, which is the relay
endpoint — **not** at a VNC server. The clone's console stays bound to Dom0's
loopback and `sandboxd` dials out to meet the browser's socket in the middle.
See `docs/architecture/live-console.md`.
