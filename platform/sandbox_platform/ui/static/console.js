/*
  The live console (DRAFT-056). Design: docs/architecture/live-console.md

  An ES module because noVNC is one. Loaded with `type="module"` from
  _job_status.html, which keeps the no-build-step property VENDOR.md argues
  for: nothing here is bundled, so what is served is what was downloaded.

  **This connects to the RELAY, not to a VNC server.** The clone's console
  stays bound to Dom0's loopback; sandboxd dials OUT and the platform pairs the
  two sockets. So the URL below is our own endpoint, and the fact that noVNC
  cannot tell the difference is the point -- it speaks RFB to something that
  moves bytes.
*/
import RFB from "./novnc/core/rfb.js";

/*
  THIS MODULE EVALUATES ONCE AND MUST SURVIVE EVERY SWAP AFTER IT.

  `job.js` refreshes `#job-live` with `htmx.ajax(..., swap: "innerHTML")` on
  each state change, and the console panel lives inside it. So the panel this
  module binds to is DESTROYED AND REBUILT on every transition through
  `console_states` -- cloning, preparing, executing, collecting.

  The script tag comes back with each swapped fragment, which looks like it
  should re-run this file and does not: a module URL is evaluated ONCE PER
  PAGE, so re-inserting the same `src` is a no-op. Bind once at load and the
  console attaches to the first panel, dies with it at the next state change,
  and never comes back -- which is what "the console only works if you reload
  the page while it is executing" looks like from the outside.

  Hence a watcher rather than a one-shot. It compares element IDENTITY, not
  presence: a swapped-in panel is a different object carrying the same id, so
  `panel !== bound` catches replacement and removal in the same test.
*/
let bound = null;   // the #console element we attached to, or null
let session = null; // its RFB, or null if construction failed

function sync() {
    const panel = document.getElementById("console");
    if (panel === bound) {
        return;
    }

    // What we were attached to is gone or has been replaced. Drop the socket
    // rather than leave it open against a domain being torn down.
    if (session) {
        session.disconnect();
    }
    session = null;
    bound = panel;

    // Null when the job left `console_states`: nothing to attach to, and the
    // next swap that brings a panel back will be picked up by the same test.
    if (panel) {
        session = start(panel);
    }
}

/*
  A state change therefore costs a reconnect, and that is honest rather than a
  regression -- the canvas the session was drawing on no longer exists. It does
  not disturb interactive work, because `job.js` swaps only when the state
  CHANGES and an operator drives a sample within `executing`.

  Deliberately no test on which state we are in. The panel's presence already
  encodes that: `_job_status.html` renders it for `console_states`, and a
  second copy of that window here would be free to drift from the first. The
  symptom of the drift is a panel offering a session the page then declines to
  open, or -- as happened on 2026-09-05 -- a JS gate on `executing` silently
  cancelling a template change that had just widened it to four states.
*/
new MutationObserver(sync).observe(document.body, {
    childList: true,
    subtree: true,
});
sync();

function start(panel) {
    const jobId = panel.dataset.jobId;
    const screen = document.getElementById("console-screen");
    const statusLine = document.getElementById("console-status");

    const say = (text) => { statusLine.textContent = text; };

    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${scheme}//${window.location.host}` +
                `/api/v1/jobs/${encodeURIComponent(jobId)}/console`;

    say("Waiting for the analysis host…");

    let rfb;
    try {
        rfb = new RFB(screen, url, {
            // No credentials: the console has no password. It is on Dom0's
            // loopback on a host nothing else reaches, and none of the five
            // misc/*.cfg sets `vncpasswd` -- so there is nothing to
            // authenticate to. The session's authentication is Cloudflare
            // Access on the WebSocket, one layer out.
            credentials: {},
            // Resize the framebuffer to the panel rather than scaling it. A
            // scaled screenshot of a phishing page is a screenshot you can
            // misread, and this is a tool for looking at things carefully.
            resizeSession: false,
            // Off. DRAFT-056 puts clipboard out of scope entirely: a separate
            // channel into a malware VM, not needed to click a button. Set
            // here as well as omitted from the vendored `app/`, because
            // "we did not ship the button" is not the same as "the feature is
            // off".
            clipboardBinary: false,
        });
    } catch (err) {
        say(`Could not start the console: ${err.message}`);
        // `sync` has already recorded this panel as the bound one, so a
        // failure here is not retried against the same element on every
        // mutation -- only against the next panel a swap brings in.
        return null;
    }

    // Scale down to fit, never up. An upscaled framebuffer invents detail.
    rfb.scaleViewport = true;
    rfb.clipViewport = true;

    rfb.addEventListener("connect", () => {
        say("Connected. Anything you type or click goes to the live sample, " +
            "and is recorded on the report.");
        panel.dataset.state = "connected";
    });

    rfb.addEventListener("disconnect", (e) => {
        panel.dataset.state = "closed";
        // `clean` distinguishes "the trace ended" from "something broke", and
        // they read very differently to an operator watching a sample.
        say(e.detail.clean
            ? "Session ended — the analysis finished or was stopped."
            : "Session lost. The job is unaffected and continues to run.");
    });

    rfb.addEventListener("securityfailure", (e) => {
        say(`Refused: ${e.detail.reason || "the relay closed the session"}`);
    });

    // Teardown belongs to `sync`, not here. This function used to install its
    // own observer that disconnected as soon as `#console` went missing, and
    // then disconnected ITSELF -- so the first swap both killed the session
    // and removed the only thing watching for the panel's return. One watcher
    // owning the whole lifecycle is what makes reattachment possible.
    return rfb;
}