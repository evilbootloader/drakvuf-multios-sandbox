/*
  Live job status.

  The SSE endpoint has existed since #36 -- snapshot-on-connect, terminal
  close, keepalives, tested in test_jobs_api.py -- and nothing in the browser
  ever subscribed to it. A job page was therefore a snapshot from the moment
  it rendered, which is what a fake_worker run showed on 2026-08-25: the
  worker walked the whole state machine and the page sat on `queued` until
  someone pressed reload.

  What arrives on the wire is only {"id": ..., "state": ...}. This deliberately
  does NOT try to render from that: it asks the server to re-render the live
  region, so every display rule (a wait that is not a failure, which tabs are
  filled, whether the failure block shows) stays in one place and stays
  autoescaped.
*/
(function () {
  "use strict";

  var root = document.getElementById("job-live");
  if (!root) return;

  var jobId = root.dataset.jobId;

  // From the server via data-terminal, not a literal here. A JS copy of
  // TERMINAL_STATES would be a second definition free to drift from
  // enums.py, and the symptom of drift is a page that reconnects forever.
  var terminal = new Set(
    (root.dataset.terminal || "").split(" ").filter(Boolean)
  );

  var state = root.dataset.state;
  var pending = false;

  var source = new EventSource(
    "/api/v1/jobs/" + encodeURIComponent(jobId) + "/events"
  );

  source.addEventListener("message", function (event) {
    var payload;
    try {
      payload = JSON.parse(event.data);
    } catch (err) {
      return; // A frame we cannot parse is not worth throwing over.
    }
    if (!payload || !payload.state) return;

    if (payload.state !== state) {
      state = payload.state;
      refresh();

      // The masthead balance is drawn down by exactly this transition, and it
      // is outside #job-live so refresh() does not touch it. Told rather than
      // polled; `balance.js` listens.
      //
      // On a CHANGE to a terminal state, not on every terminal frame. The
      // first frame is a snapshot, so opening an already-finished job would
      // otherwise refetch a balance that already includes the charge.
      if (terminal.has(payload.state)) {
        document.dispatchEvent(new CustomEvent("sandbox:balance-stale"));
      }
    }

    // Checked on EVERY frame, not only on a change. The first frame is a
    // snapshot, so opening an already-finished job yields a frame equal to
    // what is on screen -- and the server ends the stream straight after it.
    // Short-circuiting above this line would leave EventSource to do what it
    // does with a closed stream: reconnect, every few seconds, for as long as
    // the tab is open, against a job that can never change again.
    if (terminal.has(payload.state)) source.close();
  });

  function refresh() {
    if (pending) return; // States, not increments: the next frame re-reads.
    pending = true;

    // The tab you are LOOKING at, which after an htmx click is not the one
    // the URL was rendered with.
    var nav = root.querySelector(".tabs");
    var tab = (nav && nav.dataset.active) || "overview";
    var url =
      "/ui/jobs/" + encodeURIComponent(jobId) +
      "/live?tab=" + encodeURIComponent(tab);

    if (!window.htmx) {
      // htmx absent means the tab bar is inert anyway; a reload is honest.
      window.location.reload();
      return;
    }

    // htmx.ajax rather than fetch + innerHTML so the swap goes through the
    // same path a tab click does -- including processing the new nodes,
    // without which the tab links in the fresh markup are dead and the page
    // updates exactly once. No push-url: a status change is not navigation.
    window.htmx
      .ajax("GET", url, { target: "#job-live", swap: "innerHTML" })
      .catch(function () {
        // Leave the last good render up. A stale page with a live "state"
        // that stopped moving is better than a blanked one.
      })
      .finally(function () {
        pending = false;
      });
  }

  // Publication (#40, decisions 5/6).
  //
  // **Delegated on `root`, not bound to the button.** refresh() swaps this
  // region's innerHTML, so a listener attached to the button is discarded on
  // the first state change and the control goes dead with no symptom. `root`
  // is the one node in here that survives a swap.
  var publishing = false;

  function send(action, button) {
    publishing = true;
    button.disabled = true;

    // **X-Sandbox-Request is what makes this unreachable from another origin**,
    // and the server now requires it on every unsafe method.
    //
    // This comment used to credit `Content-Type: application/json` with that
    // job, and for this one call it was true: the app installs no CORS
    // middleware, so a request needing a preflight is one the browser will not
    // send cross-origin, and a simple request WOULD be sent with Cloudflare
    // injecting the victim's Access assertion on the way through. But it was a
    // property of how this particular fetch happened to be written -- two other
    // callers in this UI were sending simple requests to mutating routes at the
    // same time. The rule lives in `sandbox_platform/csrf.py` now.
    //
    // The content type stays because the body genuinely is JSON, not because it
    // is carrying the defence.
    fetch("/api/v1/jobs/" + encodeURIComponent(jobId) + "/" + action, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sandbox-Request": "1"
      }
    })
      .then(function (r) {
        if (r.ok) {
          // Re-rendered by the server rather than flipped here, for the reason
          // at the head of this file: one place decides how a job renders.
          refresh();
          return;
        }
        // 409: another tab acted while this one showed a stale state.
        // 403: served from the mTLS listener -- a deployment fault, not a user
        // error, and worth saying differently.
        throw new Error(
          r.status === 409 ? "state changed — reload"
            : r.status === 403 ? "this listener cannot publish"
            : "failed (" + r.status + ")"
        );
      })
      .catch(function (err) {
        // Loud. A security control that silently did nothing is the worst of
        // the three outcomes.
        button.disabled = false;
        var note = root.querySelector("[data-publish-error]");
        if (note) note.textContent = err.message;
      })
      .finally(function () {
        publishing = false;
      });
  }

  root.addEventListener("click", function (event) {
    var button = event.target.closest("[data-publish]");
    if (!button || publishing) return;

    // Unpublishing needs no consent: nothing has to be confirmed to become
    // less visible. Publishing is the irreversible direction -- see below.
    if (button.dataset.publish === "unpublish") return send("unpublish", button);
    confirmThenPublish(button);
  });

  function confirmThenPublish(button) {
    // Looked up per click, never cached: refresh() replaces this region's
    // innerHTML, so a reference taken at load time points at a detached node.
    var warning = root.querySelector("#publish-warning");

    if (!warning || typeof warning.showModal !== "function") {
      // No <dialog> support. Falling through to the POST would publish with no
      // warning at all, which is the one outcome this control must never have,
      // so degrade to the ugly-but-universal prompt instead.
      if (window.confirm(button.dataset.warning)) send("publish", button);
      return;
    }

    warning.returnValue = "";
    warning.addEventListener("close", function once() {
      warning.removeEventListener("close", once);
      if (warning.returnValue === "publish") send("publish", button);
    });
    warning.showModal();
  }
})();

