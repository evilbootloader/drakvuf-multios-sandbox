/*
  The report tabs' <details>: expand or collapse a whole section at once, and
  open whatever a `#proc-N` link lands inside.

  The tabs work without this. Every group and tree branch is a plain
  <details> that opens on a click, and a browser that auto-expands a closed
  <details> for a fragment link (Chromium does) needs nothing more. This adds
  the two things a page of a hundred closed groups wants on top: one button
  for all of them, and the same fragment behaviour in browsers that do not.

  **Marks <html> so the buttons exist only when they work.** They are
  `display: none` until `.has-disclose` is set (app.css, `button.ghost`): a
  control that looks available and does nothing reads as a fault.

  **Delegated on `document`, not bound to the buttons.** The tab bodies are
  swapped by htmx on every tab click and SSE refresh -- see pan.js, which
  is delegated for the same reason.
*/
(function () {
  "use strict";

  document.documentElement.classList.add("has-disclose");

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-disclose]");
    if (!button) return;
    var scope = button.closest("[data-disclose-scope]");
    if (!scope) return;
    var open = button.dataset.disclose === "open";
    // `.advanced` is a different kind of disclosure -- "all N processes as a
    // diagram" -- and expanding every group should not also draw that.
    scope.querySelectorAll("details:not(.advanced)").forEach(function (d) {
      d.open = open;
    });
  });

  // Open every closed <details> between the fragment's target and the page,
  // then bring the target into view: the browser scrolled to it, if at all,
  // while it was still hidden.
  function reveal() {
    var id;
    try { id = decodeURIComponent(window.location.hash.slice(1)); } catch (e) { return; }
    if (!id) return;
    var target = document.getElementById(id);
    if (!target) return;
    var opened = false;
    for (var d = target.parentElement && target.parentElement.closest("details");
         d; d = d.parentElement && d.parentElement.closest("details")) {
      if (!d.open) { d.open = true; opened = true; }
    }
    if (opened) target.scrollIntoView({ block: "center" });
  }

  window.addEventListener("hashchange", reveal);
  document.addEventListener("DOMContentLoaded", reveal);
})();