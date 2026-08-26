# Live console — session model and threat model

> **Status: design, not built.** Written first and deliberately, per
> DRAFT-056's own PLAN step 1: *"Write the threat model first, and get it
> reviewed before code. This is the one issue here where the design decision is
> the whole risk."* Nothing in this document has been implemented, and two
> parts of it amend the draft rather than restate it.

Letting an analyst see and drive a clone while it runs is the one capability
automation does not replace — CAPTCHAs, password-protected documents,
multi-stage phishing flows, installers that ask a real question. `hidsim`
(DRAFT-055) gets past "is anyone there"; it cannot read a dialog and answer it.

It is also **the largest deliberate widening of attack surface in this
project**. Everything else reads data that already exists. This opens an
interactive channel toward a machine running live malware.

---

## 1. Two contradictions in DRAFT-056, and how they are resolved

### 1.1 The relay direction

The draft's diagram is:

```text
browser ──TLS──> Cloudflare Access ──> platform (FastAPI) ──> Dom0 ──> clone VNC
```

and its DEPLOY section says *"Dom0 needs no new listener: the platform opens
the connection over the LAN."* Those cannot both be true — a connection **to**
Dom0 requires Dom0 to be listening. The draft also promises the console *"stays
bound to Dom0's loopback exactly as now"*, which would make it unreachable from
another machine entirely.

It collides with the deploy runbook as well. Step 5 checks that the platform
**cannot** reach Dom0:

```text
pct exec 102 -- bash -lc 'curl -m 5 -sv https://192.168.1.139/ ; echo "exit=$?"'
* Connection timed out after 5002 milliseconds
exit=28
```

with the stated invariant: *"Dom0 has no inbound listener and the platform must
never acquire a route to it."* DRAFT-056 requires that check to *"still pass
during a live session"* — impossible if the platform dials Dom0.

**Resolved 2026-08-26: Dom0 dials out.** The direction in the diagram is
reversed.

```text
browser ──WS──> platform <──WS── sandboxd ──> 127.0.0.1:59xx
                   │                 │
            pairs the two      dials OUT, exactly as it
            by job_id          already does for /claim
```

`vnclisten` stays `127.0.0.1` in all five `misc/*.cfg`. Dom0 gains no listener.
Step 5 passes unchanged, **during** a session, which is what the draft asked
for and what its own design would have prevented.

This is not a workaround. It is the shape the rest of the system already has:
**cancellation is delivered in a heartbeat response rather than pushed**,
precisely because pushing would need an inbound listener on the machine that
runs malware. A console session is the same problem and gets the same answer.

### 1.2 View-only cannot be enforced without parsing

The draft asks for two things that conflict:

> - **The relay does nothing but move bytes** — no protocol parsing, no framing
>   logic, no state beyond "which job".
> - **View-only must be enforced on the server.** A client-side flag is a
>   suggestion; the relay is what must drop input frames.

Dropping input frames *is* parsing. And the naive version — refuse to relay
anything browser→clone — does not work either: RFB requires the client to send
`ProtocolVersion`, the security response, `ClientInit`, `SetPixelFormat`,
`SetEncodings`, and a `FramebufferUpdateRequest` **for every frame it wants**.
A view-only client that sends nothing receives nothing.

**Resolved 2026-08-26: view-only is DEFERRED, and the "move bytes only"
property is kept rather than withdrawn.**

View-only exists in DRAFT-056 for one purpose — *"watch a `hidsim` run without
fighting the synthetic pointer"* — and `hidsim` is DRAFT-055, which is not
built. Nothing can request it: `Interaction.AUTOMATIC` raises
`NotImplementedError` in `sandboxd/stages.py`, and the submit form offers no
such control. The parser would be the most security-sensitive code in the
feature, written before anything could use it.

So v1 is interactive-only and the relay does exactly what the draft first
asked: moves bytes between two sockets, parses nothing, holds no state beyond
which job.

A search for an existing library confirmed there is nothing to borrow here:
`asyncvnc` and `vncdotool` are VNC *clients* — they write `KeyEvent` and
`PointerEvent`, they do not parse incoming ones — and `websockify` is
transport-only, which Starlette already provides. Filtering client→server RFB
is a proxy concern that no Python library covers, so it would have to be
written, which is another reason not to write it before it is needed.

**When DRAFT-055 lands, this is what it needs**, recorded now so it is not
re-derived:

| Type | Message | View-only |
|---|---|---|
| 0 | SetPixelFormat | pass |
| 2 | SetEncodings | pass |
| 3 | FramebufferUpdateRequest | pass — without it, no picture |
| **4** | **KeyEvent** | **drop** |
| **5** | **PointerEvent** | **drop** |
| **6** | **ClientCutText** | **drop** — also out of scope entirely |
| 7+ | anything else | **drop, and end the session** |

Two things that filter will have to get right, and that are easy to miss:

- **The handshake is client→server too.** A filter that began parsing messages
  at the first byte would read `RFB 003.008\n` as message type 0x52 and
  desynchronise. The cheapest correct answer is to admit only the shape our own
  clones present — RFB 3.8, security type None, no authentication, which is
  what all five `misc/*.cfg` give since none sets a VNC password — and end the
  session on anything else. A relay that negotiates is a relay with states
  nobody tested.
- **`FramebufferUpdateRequest` (3) must pass.** RFB requires one for every
  frame the client wants, so "drop everything client→server" yields a black
  screen rather than a view-only one.

`ClientCutText` (6) is dropped in **both** modes whenever the filter is
written, because clipboard is out of scope entirely: a separate channel into a
malware VM, not needed to click a button.

---

## 2. The session model

### 2.1 Lifetime

- **Only while the job is `executing`.** Not before the clone exists, not
  during preconfig, not after teardown. Outside that window the endpoint 409s.
- **One viewer.** A second request for the same job is refused, not queued.
- **Ends when the trace ends.** `sandboxd` closes its side as part of the
  normal teardown, so there is no orphaned relay to reap.
- **A dropped browser connection does not touch the job**, which completes
  normally. The console is an observer of the analysis, never a participant in
  its lifecycle.

### 2.2 How a session starts, without Dom0 listening

> **Revised 2026-08-26 after F8.** This section originally described a
> request-driven dial: the operator asks, `sandboxd` learns on its next
> heartbeat, then connects. **That could never have worked.** A session is
> scoped to a job that is `executing` (§2.1), so the panel only appears once
> the trace has begun — and the check for a request happened before it. Every
> request arrived too late to be seen and the browser sat at "Waiting for the
> analysis host…" until the pair timeout.

1. `sandboxd` resolves the clone's VNC port when the trace starts, opens an
   outbound WebSocket to the platform carrying the job id and the worker
   token, and bridges it to `127.0.0.1:<port>`.
2. The platform holds that socket, unpaired, for the duration of the trace.
3. When the operator opens the panel, the browser's socket is paired with it
   by job id, and bytes move immediately.

**There is no latency and no request channel.** The cost is that a relay socket
is open for *every* analysis on a host where the console is enabled, watched or
not — which is a real change to §4 and is treated there rather than glossed.

The two sides therefore wait differently. `sandboxd` holds its end for the
whole trace and closes it during teardown, on every path. The browser's end
keeps a short timeout, because a human is looking at it and should be told
promptly when nobody is there.

**There is no longer a latency floor for the console** — dialling at trace
start removed it. The heartbeat interval was lowered from 30s to **10s** on
2026-08-26 while the request-driven design was still in place; the change is
kept because it also makes cancellation land sooner and gives the lease twelve
beats instead of four, so a run of failed
beats on a busy platform no longer eats a quarter of the margin each time.

The cost is one small row `UPDATE` per beat per running job -- twelve a minute
at `MAX_CLONES=2`, against a Postgres in the same container.

> **Finding the VNC port is UNVERIFIED and must be tested on Dom0.** Two
> candidates, neither yet run:
>
> ```sh
> # Candidate A
> xenstore-read /local/domain/<domid>/console/vnc-port
> # Candidate B
> xl list -l <domain>      # JSON; vfb/vnc stanza
> ```
>
> Per CLAUDE.md these are **Candidate**, not proven, and must not be treated as
> working commands until a Dom0 session says otherwise.

### 2.3 Where it sits on the page

**Above the tab bar, always present — not a tab.** Decided 2026-08-26.

The tabs are *result* views: Overview, Behaviour, Network, Static, Memory,
Artifacts. Every one of them describes something the run produced, and every
one is read after the fact. A live console is neither — it exists only while
the job is `executing`, and it is the one thing an analyst must not have to go
looking for. A CAPTCHA does not wait for someone to click the right tab.

Making it a tab would also mean losing it on every tab change, which is the
opposite of what an interactive session needs: watch the screen *while*
reading the syscall stream.

```text
  ┌──────────────────────────────────────────┐
  │ sample.exe          state: executing     │
  ├──────────────────────────────────────────┤
  │            ▓▓ live console ▓▓            │   ← always here while executing
  │            (collapses when not)          │
  ├──────────────────────────────────────────┤
  │ Overview │ Behaviour │ Network │ Static  │   ← the result tabs, unchanged
  ├──────────────────────────────────────────┤
  │  ... tab body ...                        │
  └──────────────────────────────────────────┘
```

It collapses to nothing outside the `executing` window rather than rendering an
empty frame, for the same reason the tab bar dims tabs with no data: a control
that looks available and does nothing reads as a fault.

This sits inside `#job-live`, so the SSE refresh already re-renders it when the
state changes — appearing when the job starts executing and disappearing when
it stops, with no extra wiring.

### 2.4 Interaction is recorded as a fact about the run

A report from an interactive session is **not comparable** to an automated one:
a human made choices that changed what happened. The job records that it was
interacted with, and the report says so.

This is a correctness requirement, not bookkeeping. Two reports that look alike
must not describe different experiments. The flag is set when the first input
message is relayed — not when the session opens, because watching changes
nothing.

---

## 3. What is deliberately not built

- **Clipboard, file transfer, audio.** Each is a separate channel into a
  malware VM and none is needed to click a button. Framebuffer out, input in.
  `ClientCutText` is dropped in **both** modes, not only view-only.
- **Session recording as an artifact.** Screenshots (DRAFT-054) are the visual
  record.
- **Multi-user viewing.** One session, one viewer.
- **Reconnection.** A dropped session is reopened, not resumed.

---

## 4. Threat model

### 4.1 What the guest can reach

**The RFB server is QEMU in Dom0, not in the guest.** The device model paints
the guest's framebuffer; the guest cannot speak RFB outward. A guest that
wanted to attack a viewer would have to exploit QEMU's VNC server first — and
that is a Dom0 escape, which is a far larger problem than this feature and is
not made worse by it.

What the guest **can** do is control what is drawn. A viewer is looking at
attacker-chosen pixels. That matters for the human, not for the software: no
image can escape a canvas element, but an analyst can be socially engineered by
what a sample chooses to display.

### 4.1b A relay socket is open for every analysis

This is the cost of removing the request channel (§2.2), and it is the largest
change to this document since it was written.

`sandboxd` dials out for **every executing job** on a host where the console is
enabled, whether or not anyone is watching. `console.py` originally argued the
opposite — *"a worker with no browser is a socket into a malware VM's console
with nobody watching it, and the second is the one that matters"* — and the
worker endpoint refused an unprompted dial as *"either a bug or a compromised
Dom0 opening a channel on its own initiative"*.

Both are withdrawn, because the alternative was a feature that could not work.
What bounds it instead:

- **`CONSOLE_ENABLED` is off by default, on both sides.** Its meaning changes
  from "consoles may be requested" to **"this host opens a relay socket per
  analysis"**. That is a coherent thing to switch on deliberately, and a
  coherent thing to leave off.
- The job must be `executing`. Outside that window the endpoint refuses.
- The worker token is still required, over mutual TLS on the LAN.
- The socket terminates at the platform. Reaching it from outside still needs
  Cloudflare Access, unchanged.
- It closes with the trace, on every path.

**How much worse is it, actually?** Less than the paragraph above might
suggest, and the correction is worth making rather than leaving an
overstatement standing.

A standing socket sounds alarming and is mostly not, because of what is on the
other end of it. The relay pumps bytes **only to a paired peer**, and the only
thing that can pair is a browser that opened a console on that job and passed
Cloudflare Access. With no peer the socket sits there doing nothing: it is not
a route to any other endpoint, it cannot enumerate, and it carries no data
until someone authenticated is watching.

So for a compromised Dom0 the marginal gain is: the ability to push chosen
bytes at an operator's browser, once that operator chooses to look. Weighed
against what the worker token already grants it — `/claim`, `/state`,
`/heartbeat`, `/artifacts`, `/complete`, and presigned URLs into the object
store — that is a small addition.

It is not nothing. Feeding hostile RFB to noVNC is a real vector at the
operator's browser, and it is now reachable without anyone having asked for a
session first. But the guest already controls every pixel in that framebuffer,
so an operator opening a console is looking at attacker-chosen content either
way (§4.1).

**What is genuinely different:** one socket and one thread per analysis, and a
slightly shorter path for an attacker who already holds the credential that
matters. Both are acceptable behind a flag that is off by default; neither
would be acceptable if it were on by default, which is why it is not.

### 4.2 What a compromised platform can reach

Once a session is open the platform can send bytes toward the clone's console.
That is the feature. It does not widen anything meaningfully: a platform that
is compromised already chooses what samples run and already holds every
credential in the system.

What it **cannot** do, and must never be able to, is initiate. Dom0 dials out;
there is no port on Dom0 for a compromised platform to connect to, and no
route. That is the property step 5 checks and this design preserves.

### 4.3 What a compromised Dom0 can reach

`sandboxd` opening an outbound WebSocket is a new capability for the machine
that runs malware, and it is worth stating plainly. But Dom0 already opens
authenticated outbound connections to this exact endpoint for `/claim`,
`/heartbeat` and artifact upload. The relay adds a socket, not a trust
relationship: the same worker token, the same client certificate, the same
service.

The relay's own exposure is bounded by section 1.2 — it moves bytes between two
sockets and consults a message-type table.

### 4.4 Authentication — two sides, two mechanisms

The two halves of a session authenticate differently, and conflating them was
an error in the first draft of this document.

**Browser → platform: Cloudflare Access**, inherited because the endpoint
lives on the router that already carries the dependency. **No second auth
system exists to misconfigure**, which was the decisive argument against
Guacamole: it brings its own user and authentication model, and two auth
systems on one door is how the weaker one gets forgotten.

**Dom0 → platform: the LAN, mutual TLS, and the worker token.** It does **not**
pass through Cloudflare, and it never has — `sandboxd` reaches the platform
directly at `192.168.1.10:9000`, which is exactly what the deploy runbook's
step 5 checks succeeds. Access protects the tunnel hostname; the worker channel
is a different door on a different network, and it is already authenticated by
the client certificate the platform requires (`--ssl-cert-reqs 2`) plus the
bearer token.

So the relay socket needs no new credential in either direction. It reuses what
each side already presents:

```text
browser  ──> Cloudflare Access ──> platform      (Access JWT)
sandboxd ──> LAN, 192.168.1.10 ──> platform      (mTLS + worker token)
```

Stating this precisely matters because the two are easy to blur into "the
relay is authenticated", which would leave the reader unable to tell which
failure removes which protection. Losing Access exposes the console to the
internet; losing the client certificate exposes it to the LAN. They are not
the same incident.

> **Pre-#40, any authenticated user can open a session on any job.** There is
> one operator today, so this is acceptable — and it is written down rather
> than assumed. When ownership means something, the session must be scoped to a
> job the requester owns.

### 4.5 Residual risks, accepted

- **One heartbeat of latency** before a session opens. The cost of not
  listening.
- **The RFB message parser** is the sharpest edge. Bounded by refusing what it
  cannot parse.
- **A human driving a live sample makes outbound consequences deliberate**
  rather than incidental — DRAFT-022 applies with force, and `offline` mode
  (DRAFT-057) should be available alongside this.
- **Feature-flagged off by default.** This is the first exception to "Dom0
  never listens" — or rather, the first thing that *would* have been, and is
  not. It should still be switchable off without a redeploy while confidence is
  built.

---

## 4.6 OPEN: does `hidsim` already run, and would it fight the operator?

**Unresolved, and it must be settled on Dom0 before a console session is used
in anger.** Raised 2026-08-26.

DRAKVUF's `hidsim` plugin injects synthetic mouse and keyboard input. Its own
options describe what it does with no template:

```text
--hid-template <path>   The template specifying the HID events to simulate.
                        If not specified, THE MOUSE WILL MOVE RANDOMLY.
--hid-random-clicks     Inject random clicks and double clicks, if no template
                        is specified. Spares the bottom-left 20 percent.
```

Neither `drakvuf-ubuntu.sh:178`, `drakvuf-android.sh` nor `sandboxd/guests.py`
passes any `--hid-*` option. So whether `hidsim` runs at all depends on one
thing nobody here has established:

> **Is `-a <plugin>` restrictive or additive?** If specifying `-a syscalls -a
> filetracer -a fileextractor -a memdump` means "only these", `hidsim` has
> never run and there is nothing to reconcile. If it means "these as well as
> the defaults", every Ubuntu and Android trace this project has ever produced
> had a randomly moving mouse in it — an unrecorded fact about all of them.

The captured `drakvuf --help` in `verify-user-placeholder.md:71` was piped
through a grep for exec-related options, so the `-a` line's text is not in the
repository, and there is no DRAKVUF source checkout to read. This cannot be
answered from the desk.

**Why it matters for this feature specifically.** If `hidsim` is running, a
human driving through noVNC is fighting a synthetic pointer for control of the
same cursor. That is precisely the collision DRAFT-056's view-only mode exists
to avoid — and view-only is deferred (§1.2), so there is currently no way to
avoid it at all.

**It matters more for the traces themselves.** Random clicks in a guest are
guest behaviour that no report attributes to anything. A sample that appears to
open a file because a random double-click landed on it would be indistinguishable
from one that chose to.

Settle it with the check in the runbook. Until then the interaction between
`hidsim` and a live console is **unknown, not absent**, and DRAFT-055 should
not be planned as though starting from zero.

---

## 5. What this changes elsewhere

- **`docs/architecture/platform.md`** — the "Dom0 never listens" constraint is
  **not** amended. It survives, which is the point of the reversal in §1.1.
  What it gains is a note that a console session is an outbound socket, so a
  reader does not conclude the constraint was quietly dropped.
- **`misc/*.cfg`** — unchanged. `vnclisten = "127.0.0.1"` stays exactly as it
  is, in all five files.
- **`DRAFT-056`** — amended for both contradictions above.
- **The deploy runbook** — step 5 gains a during-session variant, and it is the
  *same* check rather than a rewritten one.
- **`ui/static/VENDOR.md`** — noVNC as the second vendored file.
