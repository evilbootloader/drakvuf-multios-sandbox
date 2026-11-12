/*
  Inline panels: whatever a row opens, it opens directly below that row, in
  a row of its own (`.xrow`, rendered hidden after it), with a close button.
  Nothing else on the page is hidden or moved out of sight, and any number
  can be open at once (operator, 2026-11-11).

  A toggle (`[data-x]`) names its panel: `#x-<id>`. A panel whose content
  is not in the page is fetched on first open from the toggle's
  `data-x-src`, by htmx, into the panel's body -- the same fragment the
  toggle's href serves as a page without script. The whole row is a toggle
  too, except where the click lands on a link, a button or a form control of
  its own.

  **Delegated on `document`, not bound to the rows.** Tab bodies, process
  panels and pages of calls are all swapped in by htmx after load; a listener
  bound at load would miss every one of them. See disclose.js and pan.js.
*/
(function () {
  "use strict";

  function buttons(id) {
    return document.querySelectorAll('.xbtn[data-x="' + CSS.escape(id) + '"]');
  }

  function setExpanded(id, open) {
    buttons(id).forEach(function (b) { b.setAttribute("aria-expanded", open ? "true" : "false"); });
    var row = document.querySelector('.xr[data-x="' + CSS.escape(id) + '"]');
    if (row) row.classList.toggle("is-open", open);
  }

  function open(id, panel) {
    panel.hidden = false;
    setExpanded(id, true);
    var src = null;
    buttons(id).forEach(function (b) { src = src || b.dataset.xSrc; });
    if (src && !panel.dataset.loaded && window.htmx) {
      panel.dataset.loaded = "1";
      var body = panel.querySelector(".xbody");
      body.setAttribute("aria-busy", "true");
      body.textContent = "Loading…";
      window.htmx.ajax("GET", src, { target: body, swap: "innerHTML" }).then(function () {
        body.removeAttribute("aria-busy");
      }, function () {
        // Fetched again on the next open rather than left saying "Loading"
        delete panel.dataset.loaded;
        body.textContent = "Could not load this. Close and open it again.";
      });
    }
  }

  function close(id, panel) {
    panel.hidden = true;
    setExpanded(id, false);
  }

  function toggle(id) {
    var panel = document.getElementById("x-" + id);
    if (!panel) return false;
    if (panel.hidden) open(id, panel); else close(id, panel);
    return true;
  }

  document.addEventListener("click", function (event) {
    if (event.defaultPrevented || event.button !== 0) return;
    var target = event.target;

    var closer = target.closest("[data-x-close]");
    if (closer) {
      var panel = closer.closest(".xrow");
      if (panel) close(panel.id.slice(2), panel);
      return;
    }

    var button = target.closest(".xbtn[data-x]");
    if (button) {
      // Modified clicks keep the link's own meaning: open the fragment in
      // a new tab.
      if (event.metaKey || event.ctrlKey || event.shiftKey) return;
      if (toggle(button.dataset.x)) event.preventDefault();
      return;
    }

    var row = target.closest(".xr[data-x]");
    if (!row) return;
    // A click on something with a meaning of its own stays that; so does
    // selecting text, which a reader of a path or a command line does a lot.
    if (target.closest("a, button, input, select, textarea, label, summary, pre, code")) return;
    var selection = window.getSelection && window.getSelection();
    if (selection && String(selection).length) return;
    toggle(row.dataset.x);
  });

  // Escape closes the panel the focus is in.
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    var panel = document.activeElement && document.activeElement.closest &&
      document.activeElement.closest(".xrow:not([hidden])");
    if (!panel) return;
    var id = panel.id.slice(2);
    close(id, panel);
    var b = buttons(id)[0];
    if (b) b.focus();
  });
})();
