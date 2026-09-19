/*
  Drag to pan the process diagrams.

  The full diagram of a 146-process run is wider and taller than its box,
  and scrollbars are a poor way to move around a picture: you want to grab
  it and pull. The box already scrolls, so panning is nothing more than
  turning pointer movement into scrollLeft/scrollTop -- no transform, no
  state of its own, and the scrollbars, the wheel and keyboard scrolling
  keep working exactly as before.

  **Delegated on `document`, not bound to the boxes.** The Behaviour tab is
  swapped in by htmx on every tab click and SSE refresh, so a listener bound
  at load time is attached to nodes that no longer exist after the first
  swap. One set of listeners on the document sees every box that will ever
  be rendered.

  **Mouse only.** A finger already pans a scrollable box natively, and a
  second handler on the same gesture fights it -- the box would move twice,
  or not at all where `touch-action` and the handler disagree. `pointerType`
  keeps the two apart.

  **A drag must not follow the link under it.** Every box in the diagram is
  an anchor to its node in the tree, so releasing a drag over one would jump
  the page to that node. The click a drag ends with is cancelled in the
  capture phase, before the anchor sees it; a press that never moved past
  the threshold is an ordinary click and goes through untouched.
*/
(function () {
  "use strict";

  var THRESHOLD = 4;   // px of movement before a press counts as a drag
  var drag = null;     // the drag in progress, or null
  var swallow = false; // the next click ends a drag and must not navigate

  document.addEventListener("pointerdown", function (event) {
    if (event.pointerType !== "mouse" || event.button !== 0) return;
    var box = event.target.closest(".pdiagram-wrap");
    if (!box) return;
    drag = {
      box: box, id: event.pointerId,
      x: event.clientX, y: event.clientY,
      left: box.scrollLeft, top: box.scrollTop,
      moved: false
    };
    // Deliberately NOT capturing the pointer here. Capture retargets the
    // pointerup to the box, and the browser then dispatches the click to the
    // common ancestor of the press and the release -- the box, not the
    // anchor under it -- so every plain click on a node stopped following
    // its link. Capture starts below, once the press has become a drag.
  });

  document.addEventListener("pointermove", function (event) {
    if (!drag || event.pointerId !== drag.id) return;
    var dx = event.clientX - drag.x;
    var dy = event.clientY - drag.y;
    if (!drag.moved) {
      if (Math.abs(dx) < THRESHOLD && Math.abs(dy) < THRESHOLD) return;
      drag.moved = true;
      drag.box.classList.add("dragging");
      // From here the movement must keep arriving even when the pointer
      // leaves the box or the window; without capture a fast drag that
      // exits the box is dropped mid-gesture and the box stops following.
      try { drag.box.setPointerCapture(event.pointerId); } catch (e) { /* not fatal */ }
    }
    drag.box.scrollLeft = drag.left - dx;
    drag.box.scrollTop = drag.top - dy;
    event.preventDefault(); // no text selection while panning
  });

  function end(event) {
    if (!drag || event.pointerId !== drag.id) return;
    var done = drag;
    drag = null;
    done.box.classList.remove("dragging");
    if (done.moved) {
      swallow = true;
      // The click, if any, is dispatched right after pointerup in the same
      // gesture; if none comes (released outside the window), do not swallow
      // an unrelated click made later.
      setTimeout(function () { swallow = false; }, 0);
    }
  }
  document.addEventListener("pointerup", end);
  document.addEventListener("pointercancel", end);

  document.addEventListener("click", function (event) {
    if (!swallow) return;
    swallow = false;
    event.preventDefault();
    event.stopPropagation();
  }, true);

  // The browser's own drag-and-drop starts on a pressed anchor and would take
  // the gesture over with a ghost image of the link -- the diagram is all
  // anchors, so it would happen on nearly every pan.
  document.addEventListener("dragstart", function (event) {
    if (event.target.closest && event.target.closest(".pdiagram-wrap")) {
      event.preventDefault();
    }
  });
})();
