# DRAFT-053: Public report links, and the `infected` packaging that makes them safe

**Status:** Drafted 2026-08-25. Not published.
**Area:** core/platform
**OS:** ALL
**Milestone:** M5
**Priority:** P2
**Depends on:** #37, #38, #39 (Access). Borrows `visibility` from #40.
**Needs Dom0:** **No.**

# Objective

Let the owner of a report publish it on a revocable link, and serve every
executable artifact as a password-protected archive.

# Context

## What "public" means here, and what it must not

Every route is behind Cloudflare Access today. The ask is a per-report opt-in
link, private by default — the shape Hybrid Analysis and tria.ge use.

The distinction that decides the design: **the analysis is public, the malware
is not.** A report is observations — hashes, techniques, network activity.
An artifact is a live sample. Those deserve different doors.

## Why `infected` stops being a nicety

#37 chose ZIP-with-`infected` for downloads while every route sat behind
Access, where it was a courtesy that stopped a browser or scanner acting on
the file mid-download.

A public link changes that. The URL is fetchable by anything that finds it:
a crawler, a link preview, a corporate proxy that pre-fetches. **The archive is
now the only thing between a public URL and a browser downloading a live
sample**, and `infected` is what makes every scanner in the path leave it
alone rather than quarantine it — or worse, execute it.

## The `extracted/` problem, named

`results/<job_id>/extracted/` holds files the sample **wrote** — dropped
payloads, unpacked stages. These are more directly dangerous than the
submitted sample, which may only have been a dropper, and DRAFT-051 will add
reconstructed executables on top.

Publishing a report that links to them is publishing malware. That is what
every public sandbox does, and it is defensible — but deliberately, with the
archive convention holding, rather than by not having thought about it.

# Dependencies

- **#37** — presigned GETs; the packaging happens where they are minted.
- **#38** — the report and a control to publish it.
- **#39** — the Access application the public route must sit *outside*.
- **#40** — reserves `visibility`; this borrows it early and must not
  contradict what #40 does with it.

# Out of scope

- **Accounts, sharing with named users, expiry policies.** #40.
- **Making the whole instance public.** Opt-in per report.
- **Redacting reports.** A public report shows what the private one shows. A
  redaction feature implies a classification model that does not exist.

# PLAN

1. `visibility` and `public_token`, with publish and revoke.
2. The `/r/` route, rendering the same template minus the owner.
3. The Access exclusion — a Cloudflare change, so it needs its own runbook
   step and its own evidence.
4. Archive packaging at serve time.

# CREATE

## The route

```text
GET /r/<token>          no Access, no login, read-only
jobs.visibility         private | public      (default private)
jobs.public_token       random, revocable, unique
```

A **token, not the job id.** The id appears in URLs, logs and object keys;
minting a separate secret means publishing is a deliberate act and revoking is
possible without destroying the job.

Revocation clears the token. A new publish mints a new one — an old link is
dead rather than resurrected, which is what someone revoking expects.

## Where it sits relative to Access

#37 path-routed the object store to `/analysis` on the API's hostname so the
browser upload is same-origin, and Access covers the whole hostname. `/r/` has
to be **excluded from the Access application** — a separate concern from the
tunnel's ingress rules, and the one piece here that touches Cloudflare.

That exclusion is the entire public attack surface. It must serve exactly one
thing: a read-only rendering of one job.

## Packaging

Every artifact download is a ZIP encrypted with `infected`, except those that
are plainly inert and useful to read directly — `manifest.json`, `capa.json`,
`static.json`, `network.json`. Everything derived from sample bytes is
wrapped: the sample, `extracted/`, memdumps, and DRAFT-051's reconstructed
payloads.

**Wrapped at serve time, not stored wrapped.** The worker uploads raw bytes;
the platform wraps on the way out. Storing wrapped would mean unwrapping for
every analysis step that reads a dump.

## What a public report shows

Everything the private one does, minus the owner. `jobs.owner` is an email
address and publishing a report must not publish who submitted it.

# TEST

1. **A private report 404s on `/r/<token>`** before publishing, and the token
   is absent from the database until then.
2. **A published report renders without an Access session**, proven from a
   client with no cookie and no token.
3. **Revocation kills the link** immediately, and re-publishing mints a
   different token.
4. **`/r/` is outside Access and nothing else is** — asserted against the
   deployment, since this is a Cloudflare configuration rather than code.
5. **A public report does not disclose `owner`.**
6. **Every executable artifact downloads as an `infected` ZIP**, including
   `extracted/` and memdumps, and the archive really is encrypted.
7. **A public token cannot be guessed or enumerated** — enough entropy, and no
   endpoint that lists tokens or confirms one exists.
8. **The token does not appear in logs.**
9. **Retention still applies.** A public link to an expired report says so
   rather than 404ing as though the report never existed.

# DEPLOY

Two halves that must land in order: **packaging first, the public route
second**. A public link to unwrapped executables is the one sequence that
must not happen, even briefly.

The Access exclusion is a dashboard change and belongs in the deploy runbook
with a transcript, like #37's step 26.

# Acceptance criteria

- [ ] Private by default; publishing is explicit and revocable.
- [ ] `/r/<token>` outside Access, read-only, one job.
- [ ] `owner` never disclosed publicly.
- [ ] All sample-derived artifacts served as `infected` ZIPs, wrapped at serve
      time.
- [ ] Tokens are unguessable, unenumerable, and absent from logs.
- [ ] `visibility` used compatibly with #40's plans.

# Evidence required

- A published report fetched with no Access session, and the same URL after
  revocation.
- An `extracted/` download, showing the archive is encrypted.
- The Cloudflare Access configuration showing `/r/` excluded and nothing else.

# Security considerations

- **This is the first unauthenticated route in the platform.** Everything
  else, including the object store since #37, sits behind Access. The whole
  security review of this issue is that one exclusion.
- **A public link is a malware distribution URL.** Defensible and normal for a
  sandbox, but it should be a decision on the record: DRAFT-022 owns whether
  this lab, on a residential line and operated personally, wants to be one.
- **Crawlers will find published links.** `noindex` and a `robots.txt` are
  worth having and are not a control — anything that fetches the URL gets the
  bytes.
- **Enumeration is the obvious attack.** A predictable token turns opt-in
  publication into "every report is public". Random, long, and never
  confirmed-by-error-message.
- **The public renderer is the same template as the private one**, which is
  good for consistency and means any field added later is public by default.
  The owner exclusion must be structural rather than a filter someone
  remembers to apply.

# Documentation changes

- **New:** the publish/revoke model and the Access exclusion, in the deploy
  runbook — it is a Cloudflare change, so it needs a step and evidence.
- **Updated:** `docs/architecture/platform.md` — an unauthenticated route now
  exists.
- **Updated:** DRAFT-022 with the distribution question.

# Recovery / rollback

Set every `visibility` to private and remove the Access exclusion. Links die;
nothing else changes.
