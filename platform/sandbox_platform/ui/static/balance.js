/* Remaining analysis seconds, in the masthead. Issue #40 (DRAFT-047), decision 8.
 *
 * Its own file rather than a block in theme.js, for two reasons. theme.js is
 * loaded WITHOUT defer so the stored theme applies before the first paint, and
 * hanging a network round trip off that works against the one reason it is
 * shaped that way. And it is a separate IIFE: the first version called a
 * `post()` helper that lives inside submit.js's closure, which is not in scope
 * here -- the page threw `post is not defined` on every load, and the browser
 * tests caught it as a stray pageerror rather than as anything about balances.
 *
 * POST, not GET, even though this reads. The endpoint creates the tenant row on
 * first contact, and a GET response is cacheable by whatever sits in front of
 * the listener -- which is Cloudflare, where a cache rule matching /api/v1/
 * would serve one tenant's balance to another. See routers/account.py.
 */

(function () {
    "use strict";

    var slot = null;
    var pending = false;

    function load() {
        // States, not increments: a second request while one is in flight
        // would return the same number, and the frame that prompted it is
        // already covered by the answer coming back.
        if (!slot || pending) { return; }
        pending = true;

        // X-Sandbox-Request: with only `Accept` this was a CORS-simple request,
        // so a cross-site page could issue it. See sandbox_platform/csrf.py.
        fetch("/api/v1/account/balance", {
            method: "POST",
            headers: {
                "Accept": "application/json",
                "X-Sandbox-Request": "1"
            },
        }).then(function (r) {
            if (!r.ok) { throw new Error("balance: HTTP " + r.status); }
            return r.json();
        }).then(function (seconds) {
            slot.textContent = seconds + "s";
            slot.title = seconds + " analysis seconds remaining";
            // Negative is a real state, not an error: the charge lands when a
            // job finishes and nothing caps a running one, so a job admitted
            // with seconds left can overdraw. Flagged rather than hidden --
            // the next submission is what gets refused.
            slot.classList.toggle("balance-low", seconds <= 0);
        }).catch(function () {
            // Left blank deliberately. A balance that failed to load is not
            // worth an error in the masthead of every page, and every route
            // that spends seconds reports its own refusal.
            slot.textContent = "";
        }).finally(function () {
            pending = false;
        });
    }

    document.addEventListener("DOMContentLoaded", function () {
        slot = document.getElementById("balance");
        if (!slot) { return; }

        load();

        /*
          Reloaded when a job is charged, because a number that only moves on
          F5 is the same fault the live status region was built to fix -- an
          operator watching a job finish saw the balance it was drawn from
          stay put. Observed on the deployment 2026-09-15, runbook 17 step 12.

          The charge and the state transition commit TOGETHER --
          `_charge_for_runtime` in routers/worker.py runs on the cursor that
          writes the terminal state -- so anything that hears about the state
          is already able to read the new balance. There is no window where
          this refetches the old number.

          Two signals, because the two live views are built differently, and
          neither one polls this route on a timer of its own:
        */

        // The job page. `job.js` dispatches this on the SSE frame that ends a
        // job it is watching. A custom event rather than a function it calls:
        // both files are plain scripts with no module graph between them, and
        // a shared global would have to be defended against load order.
        document.addEventListener("sandbox:balance-stale", load);

        // The history page, which has no SSE -- the NOTIFY channel is per job
        // id, so the list polls instead. The swap IS the signal: that poll
        // only runs while a row on the page can still change, so this stops
        // when the page stops, and a history of finished work fetches nothing.
        //
        // Filtered on the target id. The job page swaps too, through the same
        // htmx, and its swaps are already covered by the event above.
        document.body.addEventListener("htmx:afterSwap", function (event) {
            if (event.target && event.target.id === "jobs-table") { load(); }
        });
    });
}());