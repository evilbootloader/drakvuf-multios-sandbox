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
})();