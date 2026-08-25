# DRAFT-056: Live interactive analysis — noVNC over a relay we own

**Status:** Drafted 2026-08-25. Not published.
**Area:** core/platform
**OS:** ALL — Xen's QEMU device model gives every HVM guest a VNC console
regardless of guest OS.
**Milestone:** M6
**Priority:** P3. Wanted, and the one capability here that genuinely enlarges
the attack surface.
**Depends on:** DRAFT-060, DRAFT-054, DRAFT-052 (input mode), #39 (Access),
#40 (ownership).
**Needs Dom0:** **Yes.**

# Objective

Let an analyst see and control a clone while it runs, from the browser.

# Context

## The gap this closes

The comparison document's clearest finding is that interactive detonation is
what ANY.RUN is *for*, and it is the one thing automation does not replace:
CAPTCHAs, password-protected documents, multi-stage phishing flows, installers
that ask a real question. `hidsim` (DRAFT-055) gets past "is anyone there"; it
cannot read a dialog and answer it.

## Why this one gets its own threat model

Every other capability in this set reads data that already exists. This one
**opens an inbound interactive channel into a machine running live malware**,
and reverses a property held from the beginning:

> **Dom0 opens every connection here and the platform never calls back.**
> That is the hardest constraint in `platform.md`, and it shapes the whole
> worker channel — cancellation is delivered in a heartbeat *response* rather
> than pushed, because pushing would require an inbound listener on the
> machine that runs malware.

This cannot be built without deciding, explicitly, that the exception is worth
it — and confining it so the exception stays one.

# The decision: noVNC and a relay we write

**Rejected: Apache Guacamole.** It is `guacd` plus a Java web application on
Tomcat, built from source. On a container whose security argument rests on
holding every credential and therefore staying small, that is a servlet
container, a JVM and a Maven build for one feature. It also brings **its own
user and authentication model**, which would sit beside Cloudflare Access
doing the same job differently — two auth systems on one door is how the
weaker one gets forgotten. Its RDP and SSH support buys nothing, since Xen
gives us VNC for every guest including Windows.

**Chosen: noVNC as the client, and the relay as an endpoint in the existing
app.**

```text
browser ──TLS──> Cloudflare Access ──> platform (FastAPI) ──> Dom0 ──> clone VNC
                       │                      │                 │
                  authenticated       WebSocket endpoint    LOCAL only,
                  already, for free   ~50 lines of relay    never exposed
```

Starlette has native WebSocket support, so the relay is an endpoint on the
existing router. Three consequences, and each is a security property rather
than a convenience:

- **Access applies automatically**, because the endpoint lives on the router
  that already carries the dependency. No second auth system exists to
  misconfigure.
- **The relay does nothing but move bytes** — no protocol parsing, no framing
  logic, no state beyond "which job". That was the property the threat model
  wanted from it, and writing it ourselves is what makes it achievable;
  a general-purpose gateway necessarily does more.
- **websockify is unnecessary.** Its entire job is WebSocket↔TCP, which is the
  endpoint above.

noVNC also has a **view-only mode**, so one client serves both cases: watch a
`hidsim` run without fighting the synthetic pointer, or take control in an
interactive one. One flag rather than two implementations.

The honest cost: noVNC is a few hundred KB against htmx's 50, and a second
entry in `ui/static/VENDOR.md`. Worth it — the alternative is writing an RFB
protocol client.

## What must stay true

**Nothing on the internet can reach Dom0.** The deploy runbook's step 5 checks
this and must still pass *during* a live session. Dom0's side is a connection
the platform opens to it over the LAN; the clone's VNC console stays bound to
Dom0's loopback exactly as now.

# Dependencies

- **DRAFT-060** — knows which clone belongs to which job.
- **DRAFT-054** — the framebuffer plumbing.
- **DRAFT-052** — `input_mode=interactive`, mutually exclusive with `hidsim`.
- **#39** — Access is the authentication.
- **#40** — "a job you own" needs ownership to mean something. Until then any
  authenticated user can reach any session: acceptable for one operator, and
  written down rather than assumed.

# Out of scope

- **Clipboard, file transfer, audio.** Each is a separate channel into a
  malware VM and none is needed to click a button. Framebuffer out, input in.
- **Session recording as an artifact.** Screenshots cover the visual record.
- **Multi-user viewing.** One session, one viewer.

# PLAN

1. Write the threat model **first**, and get it reviewed before code. This is
   the one issue here where the design decision is the whole risk.
2. Relay endpoint, doing nothing but moving bytes.
3. Vendor noVNC; wire view-only.
4. Re-run the deploy runbook's step-5 reachability check during a live
   session — the property that must survive.

# CREATE

## Scope of a session

- Only while the job is **executing** — not before the clone exists, not after
  teardown.
- Only for a job the requester **owns** (#40); pre-#40, any authenticated user,
  with the limitation recorded.
- Ends when the trace ends. One viewer.

## Interaction is recorded as a fact about the run

A report from an interactive session is **not comparable** to an automated
one: a human made choices that changed what happened. The job records that it
was interacted with and the report says so — otherwise two reports that look
alike describe different experiments.

# TEST

1. **A session reaches the clone** and input arrives — the framebuffer changes
   in response.
2. **A session cannot be opened** for someone else's job (post-#40), or for a
   job that is not executing.
3. **The session ends when the trace does**, with no orphaned relay.
4. **Dom0 gains no internet-reachable listener** — the deploy runbook's step-5
   check still fails to connect from outside, run **during** a live session.
5. **Access is required**, proven from a client with no session.
6. **View-only really is view-only** — input from a view-only client reaches
   nothing.
7. **Interaction is recorded on the job** and rendered on the report.
8. **A dropped connection does not wedge the job**, which completes normally.

# DEPLOY

The relay is part of the existing API service, so it deploys with it. Dom0
needs no new listener: the platform opens the connection over the LAN.

**Deploy behind a feature flag, default off.** This is the first exception to
"Dom0 never listens" and it should be switchable off without a redeploy while
confidence is built.

# Acceptance criteria

- [ ] noVNC client vendored and recorded in `VENDOR.md` with its hash.
- [ ] Relay is an endpoint on the existing router, inheriting Access.
- [ ] Framebuffer and input only — no clipboard, no file transfer.
- [ ] Session scoped to one executing job, one viewer, ending with the trace.
- [ ] Dom0 exposes nothing to the internet — re-verified during a session.
- [ ] View-only mode enforced server-side, not only in the client.
- [ ] Interaction recorded and shown, so reports stay comparable.
- [ ] The `platform.md` constraint is amended deliberately, not silently.

# Evidence required

- A session driving a clone, with framebuffer response.
- Step 5's reachability check re-run **during** a session.
- The refusal cases, and a view-only client failing to send input.
- A report showing the interaction flag.

# Security considerations

- **This is the largest deliberate widening of attack surface in the project.**
  Everything else reads existing data. Stated here so the review is about that
  rather than about WebSocket plumbing.
- **The relay is a path toward Dom0.** A flaw in it is a flaw in the component
  between the internet and the machine running malware. It must relay bytes,
  terminate on job end, and hold no parsing logic — which is precisely why a
  small endpoint we own beats a general-purpose gateway that necessarily does
  more.
- **View-only must be enforced on the server.** A client-side flag is a
  suggestion; the relay is what must drop input frames.
- **VNC on a malware VM is an old and well-attacked surface.** The clone's
  console stays on Dom0 loopback; the relay is the only thing that speaks to
  it.
- **Interaction destroys comparability.** Two runs of the same sample, one
  interactive, are different experiments. The flag is a correctness
  requirement, not bookkeeping.
- **DRAFT-022 applies with force.** A human driving a live sample on a
  residential line makes outbound consequences deliberate rather than
  incidental, and `offline` mode (DRAFT-057) should be available alongside.

# Documentation changes

- **New:** the session model and its threat model, as a document rather than a
  paragraph.
- **Updated:** `docs/architecture/platform.md` — the "Dom0 never listens"
  constraint gains its first exception, with the reasoning.
- **Updated:** the deploy runbook — step 5's check gains a during-session
  variant.
- **Updated:** `ui/static/VENDOR.md` — noVNC as the second vendored file.

# Recovery / rollback

Disable the route and the relay. Analyses continue automated; nothing else
depends on it.
