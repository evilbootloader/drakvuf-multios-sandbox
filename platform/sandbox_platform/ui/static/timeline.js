/*
  The Timeline tab's window (tabs/_timeline_block.html), and the Network
  tab's per-detection timelines (tabs/_timeline_matches.html).

  - Marks the search text in yellow in every row the server marked as
    holding it (`data-hit`): DOM text nodes split around each occurrence,
    a <mark> made with textContent -- the sample's text never passes through
    an HTML parser here.
  - Brings the row a search or a row number landed on (`data-target`) to the
    top of the window -- once, when its block arrives. Rows loading as the
    reader scrolls away from it, a panel opening and a search's progress
    line settle here too, and each pulled the view back to that row until
    2026-11-15.
  - Keeps the view still when "earlier" rows load above it: they arrive
    above what the reader is looking at, and without this the window would
    jump by their height (scroll anchoring does not hold at scrollTop 0).
  - Starts a search where the reader is: after the marked row, or at the top
    row in view once they have scrolled away from it.
  - "stop" ends a search that is still reading the file; Shift+Enter in the
    search box searches up.

  Delegated on `document`, for the reason expand.js gives: the tab body is
  swapped in by htmx after load, and so is every window of rows.
*/
(function () {
  "use strict";

  function needleOf(el) {
    var holder = el.closest ? el.closest("[data-q]") : null;
    return holder ? holder.getAttribute("data-q") : "";
  }

  function mark(root, q) {
    if (!q) return;
    var needle = q.toLowerCase();
    root.querySelectorAll("tr[data-hit] .tl-text, tr[data-hit] .tl-name").forEach(function (cell) {
      if (cell.dataset.marked) return;
      cell.dataset.marked = "1";
      var walker = document.createTreeWalker(cell, NodeFilter.SHOW_TEXT);
      var nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach(function (node) {
        var text = node.nodeValue, lower = text.toLowerCase(), at = lower.indexOf(needle);
        if (at < 0) return;
        var frag = document.createDocumentFragment(), from = 0;
        while (at >= 0) {
          frag.appendChild(document.createTextNode(text.slice(from, at)));
          var m = document.createElement("mark");
          m.textContent = text.slice(at, at + needle.length);
          frag.appendChild(m);
          from = at + needle.length;
          at = lower.indexOf(needle, from);
        }
        frag.appendChild(document.createTextNode(text.slice(from)));
        node.parentNode.replaceChild(frag, node);
      });
    });
  }

  function headHeight(win) {
    var head = win.querySelector("thead");
    return head ? head.getBoundingClientRect().height : 0;
  }

  // A block the server sends has no `data-placed`: a search that lands, a
  // row number, a process chosen, the tab itself. Everything else swaps in
  // inside a block already placed, and leaves the view where the reader is.
  function toTarget(block, page) {
    if (block.dataset.placed) return;
    block.dataset.placed = "1";
    var win = block.querySelector(".tl-window");
    var row = win && win.querySelector("tr[data-target]");
    if (!row) return;
    win.scrollTop += row.getBoundingClientRect().top - win.getBoundingClientRect().top - headHeight(win);
    if (page) block.scrollIntoView({ block: "start" });
  }

  function settle(root, page) {
    var blocks = root.id === "timeline" ? [root] : root.querySelectorAll("#timeline, .tl-matches");
    blocks.forEach(function (block) {
      mark(block, needleOf(block));
      if (block.id === "timeline") toTarget(block, page);
    });
    // A window of rows appended or prepended to one already there
    if (root.closest) {
      var holder = root.closest("[data-q]");
      if (holder) mark(holder, needleOf(holder));
    }
  }

  // Earlier rows: measure before they land, restore the view after
  var pending = null;
  document.addEventListener("htmx:beforeSwap", function (event) {
    var edge = event.detail.target;
    if (edge && edge.matches && edge.matches("tr.tl-edge[data-edge='up']")) {
      var win = edge.closest(".tl-window");
      if (win) pending = { win: win, height: win.scrollHeight, top: win.scrollTop };
    }
  });
  document.addEventListener("htmx:afterSwap", function () {
    if (!pending) return;
    var p = pending;
    pending = null;
    p.win.scrollTop = p.top + (p.win.scrollHeight - p.height);
  });

  document.addEventListener("htmx:afterSettle", function (event) {
    var target = event.detail.target;
    // An outerHTML swap leaves the target detached: the block now in its place
    if (!target || !target.isConnected) target = document.getElementById("timeline") || document.body;
    settle(target.closest && target.closest("#timeline") ? target.closest("#timeline") : target, false);
  });

  document.addEventListener("DOMContentLoaded", function () {
    settle(document.body, Boolean(document.querySelector("#timeline[data-target]")));
  });

  // A search starts where the reader is
  document.addEventListener("htmx:configRequest", function (event) {
    var form = event.detail.elt;
    if (!form || !form.matches || !form.matches("form.tl-search")) return;
    var block = form.closest("#timeline");
    var win = block && block.querySelector(".tl-window");
    if (!win) return;
    var params = event.detail.parameters;
    var dir = params.dir === "prev" || (params.get && params.get("dir") === "prev") ? "prev" : "next";
    var same = (params.q || (params.get && params.get("q")) || "") === block.getAttribute("data-q");
    var top = win.getBoundingClientRect().top + headHeight(win);
    var target = win.querySelector("tr[data-target]");
    var start = null;
    if (target && same) {
      var r = target.getBoundingClientRect();
      // Still in view: from the marked row; scrolled away: from the view
      if (r.bottom > top && r.top < win.getBoundingClientRect().bottom) {
        start = Number(target.dataset.i) + (dir === "next" ? 1 : 0);
      }
    }
    if (start === null) {
      var rows = win.querySelectorAll("tr.tl-row");
      for (var i = 0; i < rows.length; i++) {
        if (rows[i].getBoundingClientRect().bottom > top) {
          start = Number(rows[i].dataset.i);
          break;
        }
      }
    }
    if (start !== null && !isNaN(start)) params.start = String(start);
  });

  document.addEventListener("click", function (event) {
    var stop = event.target.closest && event.target.closest("[data-tl-stop]");
    if (!stop) return;
    var status = stop.closest("#tl-status");
    if (!status) return;
    if (window.htmx) window.htmx.trigger(status, "htmx:abort");
    var done = document.createElement("p");
    done.id = "tl-status";
    done.className = "tl-status";
    done.setAttribute("aria-live", "polite");
    done.textContent = "Search stopped.";
    status.replaceWith(done);
  });

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Enter" || !event.shiftKey) return;
    var input = event.target;
    var form = input && input.closest && input.closest("form.tl-search");
    if (!form) return;
    event.preventDefault();
    // A click, not requestSubmit(up): htmx takes the submitting button --
    // and with it dir=prev -- from the click it saw
    var up = form.querySelector("button[value='prev']");
    if (up) up.click();
  });
})();
