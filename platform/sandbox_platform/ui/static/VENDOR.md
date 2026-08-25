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

It buys two behaviours and no build step: swapping the plugin picker when the
target OS changes, and swapping a tab body without a full page load. That is
the whole of it.

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
custom code under any framework.

## Upgrading

Change the version, re-download, update the hash above, and re-run
`tests/test_ui_browser.py` — the browser tests are what would actually catch a
regression in the swap behaviour.