# DRAFT-054: Screenshots — a filmstrip from the Xen framebuffer

**Status:** Drafted 2026-08-25. Not published.
**Area:** enrichment
**OS:** **ALL three.** Every guest here is a desktop: Ubuntu's golden VM stages
to `/home/carlos/Desktop`, BlissOS is Android with a UI, and Windows is an
HVM desktop install.
**Milestone:** M5
**Priority:** P2
**Depends on:** DRAFT-060 (a place to put the capture loop).
**Needs Dom0:** **Yes.**

# Objective

Capture the guest's screen periodically during a run and show the sequence in
the report.

# Context

## Why this is cheap here

Xen HVM guests expose a VNC console — `misc/*.cfg` already configures the
domains, and a clone inherits it. Capturing a framebuffer from Dom0 needs no
agent in the guest, no plugin, and nothing installed. It is the same agentless
argument DRAKVUF makes, applied to the display.

Every sandbox in the comparison document offers screenshots. It is often the
first thing a person looks at, and for a ransom note or a fake installer
dialog it can be more informative than the syscall trace.

## What it is actually for

Not decoration. Three concrete uses, and the first is the common one:

- **A sample that did nothing.** A trace showing a process starting and
  exiting says little. A screenshot showing an error dialog — a missing
  library, a .NET prompt, "this app can't run on your PC" — says exactly what
  happened, and that is the commonest reason a run produces nothing. It is
  also the case DRAFT-059 exists to fix, so screenshots are how you find out
  you needed it.
- **Ransom notes and lock screens**, which are the payload rather than
  evidence of it.
- **Anything needing interaction**, which is the argument for DRAFT-055 and
  DRAFT-056 and is invisible without seeing the screen.

## The real caveat, which is not about Ubuntu

All three guests have a desktop, so all three are worth capturing. The limit
is the **sample**, not the guest: one that draws nothing produces an
unchanging filmstrip, on any OS. That is a perfectly good result and needs no
special handling — the strip simply shows a desktop that did not change, which
a reader understands immediately.

# Dependencies

- **DRAFT-060** — the capture loop runs alongside the trace.
- **#37** — frames as artifacts, inside the per-job byte budget.

# Out of scope

- **Encoded video** — mp4/webm, ffmpeg. Playback is a UI feature over frames
  that already exist (see below); *encoding* is a codec dependency and a
  second copy of the same data for no additional information.
- **Deduplicating identical frames.** Considered and dropped: it saves modest
  storage and buys a real problem, since dropping unchanged frames makes the
  surviving ones unevenly spaced and playback would then have to reconstruct
  elapsed time from timestamps or silently compress it. Every frame kept, at a
  fixed interval, is both simpler and honest by construction.
- **Interaction.** DRAFT-055 and DRAFT-056.
- **OCR or classification.** Reading a ransom note automatically is a
  different project.

# PLAN

1. Capture from Dom0 against a clone's console, out of band.
2. Confirm it does not perturb the trace before building anything on it.
3. Store per job; render the strip.
4. Playback over the stored frames.

# CREATE

## Capture

From Dom0, against the clone's VNC console, at a fixed interval — 2s is a
reasonable start, and DRAFT-050's cost measurements say whether it competes
with the trace for I/O. Frames to `results/<job_id>/screenshots/NNN.png`.

**Every frame is kept.** 180s at 2s is 90 frames; a mostly-static desktop
compresses to well under a megabyte each, so a run costs single-digit
megabytes against #37's 4 GiB per-job budget. Cheap enough that discarding
frames buys nothing worth the complication.

## Presentation — a strip, and playback over it

A strip in the report, ordered, with elapsed time on each frame.

**Plus a play control that steps through them in place**, one frame every two
seconds. No encoding, no new artifact, no ffmpeg — the frames are already
stored and already fetched by the page. It is a few lines over the strip, and
it is how anyone actually reads a sequence: watching a dialog appear is faster
than comparing thumbnails.

Playback is truthful **because nothing was dropped**. Every frame is two
seconds after the last, so playing them at two seconds each reproduces the run
at real speed, and the elapsed clock on screen means what it says. Had
identical frames been discarded, fixed-interval playback would have silently
compressed idle stretches — three minutes of nothing followed by a ransom note
would replay as though both happened at once.

Frames stay individually downloadable. A screenshot of a ransom note is
evidence someone wants as a file, not as a moment in a slideshow.

# TEST

1. **A guest that draws something produces distinct frames** — a fixture that
   opens a window at a known moment, and the frame at that moment shows it.
   Run on all three guests, since all three have a desktop.
2. **A sample that draws nothing yields a full strip of an unchanged
   desktop** — every frame present, so the run's duration is visible.
3. **Capture does not disturb the trace.** Same sample with and without
   capture, syscall traces compared — this reads the framebuffer from outside,
   so any difference is a problem worth knowing about.
4. **A clone that never finishes booting produces frames showing that**, which
   is the most useful failure case there is.
5. **Frames stop when the domain is destroyed**, and no capture loop outlives
   its job.
6. **Storage is bounded** — a pathological run cannot fill the volume, and
   #37's per-job byte budget covers frames.

# DEPLOY

Part of `sandboxd`, started with the trace and stopped with the domain. No
platform change beyond rendering — frames are ordinary artifacts under #37's
existing budget and retention.

# Acceptance criteria

- [ ] Frames captured from Dom0 with nothing installed in any guest.
- [ ] Working on all three targets.
- [ ] Every frame retained at a fixed interval, timestamped.
- [ ] No measurable effect on the trace.
- [ ] Capture stops with the domain.
- [ ] Bounded by the per-job byte budget.
- [ ] Playback steps through the stored frames with no encoding step and
      no additional artifact, at the capture interval.

# Evidence required

- A filmstrip from each guest, for a sample that draws a window.
- Trace comparison with and without capture.
- A run where the guest failed to start, and the frames that show it.

# Security considerations

- **Screenshots are the most casually shareable artifact**, and a ransom note
  may contain a victim identifier, a wallet address, or content from a real
  infection. DRAFT-022's concern applies, and harder to #37's public links
  than to a trace nobody reads.
- **The framebuffer is read from Dom0**, so the guest cannot forge or suppress
  a frame — the same integrity argument as VMI, and worth stating because
  screenshots from an in-guest agent do not have it.
- **A VNC console on a malware VM is an inbound surface.** Reading it locally
  from Dom0 is fine; exposing it is DRAFT-056's problem and its threat model.
- **Frames are large.** An unbounded capture loop is the easiest way to fill
  the store, which is why #37's per-job budget must cover them rather than
  only DRAKVUF's own output.

# Documentation changes

- **New:** the capture mechanism and the deduplication rule.
- **Updated:** `docs/architecture/result-schema.md` — `screenshots/`.

# Recovery / rollback

Stop capturing. Existing frames stay; the strip renders empty.
