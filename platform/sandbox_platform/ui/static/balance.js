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

    document.addEventListener("DOMContentLoaded", function () {
        var slot = document.getElementById("balance");
        if (!slot) { return; }

        fetch("/api/v1/account/balance", {
            method: "POST",
            headers: {"Accept": "application/json"},
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
        });
    });
}());