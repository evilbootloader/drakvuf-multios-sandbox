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

const panel = document.getElementById("console");
if (panel) {
    start(panel);
}

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
        return;
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

    // The job page re-renders its status region on every state change, which
    // is what makes the panel appear when the job starts executing. When it
    // disappears -- because the job stopped executing -- the RFB object would
    // otherwise keep a socket open against a domain being torn down.
    const observer = new MutationObserver(() => {
        if (!document.getElementById("console")) {
            rfb.disconnect();
            observer.disconnect();
        }
    });
    observer.observe(document.body, { childList: true, subtree: true });
}