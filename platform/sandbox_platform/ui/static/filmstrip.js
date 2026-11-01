/*
  The Screenshots tab's player (DRAFT-054): step through the frames, or play
  them at the interval they were captured at.

  **Playback is real time because nothing was dropped.** sandboxd names every
  frame after its tick and keeps them all, so the wait before the next frame
  is (its tick - this tick) x the interval: a tick that produced no frame holds
  the previous one for the time it really covered, instead of compressing it
  away. No encoding, no video -- the frames already on the page, swapped in
  place.

  **Delegated on `document`, not bound to the elements.** The tab body is
  swapped by htmx on every tab click -- see pan.js and disclose.js, which are
  delegated for the same reason. A strip that has been swapped out stops its
  own timer (`isConnected`), so leaving the tab mid-playback leaks nothing.

  Marks <html> so the buttons exist only when they work (app.css,
  `.filmstrip-js`). Without this script every frame is still a link to its
  image.

  Text goes in through `textContent` and URLs through `src`/`href` from the
  `data-` attributes the server rendered -- never markup.
*/
(function () {
  "use strict";

  document.documentElement.classList.add("has-filmstrip");

  var timer = null;
  var playing = null;   // the strip being played, if any

  function frames(strip) {
    return Array.prototype.slice.call(
      strip.querySelectorAll("[data-filmstrip-frame]"));
  }

  function current(strip) {
    var list = frames(strip);
    for (var i = 0; i < list.length; i++) {
      if (list[i].getAttribute("aria-current") === "true") return i;
    }
    return 0;
  }

  function show(strip, index) {
    var list = frames(strip);
    if (!list.length) return 0;
    index = Math.max(0, Math.min(index, list.length - 1));
    var frame = list[index];
    list.forEach(function (el) { el.removeAttribute("aria-current"); });
    frame.setAttribute("aria-current", "true");

    var main = strip.querySelector("[data-filmstrip-main]");
    if (main) {
      main.src = frame.dataset.src;
      main.alt = "The guest's screen at " + frame.dataset.label;
    }
    var open = strip.querySelector("[data-filmstrip-open]");
    if (open) open.href = frame.dataset.src;
    var clock = strip.querySelector("[data-filmstrip-clock]");
    if (clock) clock.textContent = frame.dataset.label;
    var mark = strip.querySelector("[data-filmstrip-mark]");
    if (mark) {
      mark.textContent = frame.dataset.mark || "";
      mark.hidden = !frame.dataset.mark;
    }
    var download = strip.querySelector("[data-filmstrip-download]");
    if (download) download.href = frame.dataset.download;

    // Keep the current thumbnail in view without scrolling the page.
    var line = strip.querySelector("[data-filmstrip-strip]");
    if (line) {
      var left = frame.offsetLeft - (line.clientWidth - frame.offsetWidth) / 2;
      line.scrollTo({ left: Math.max(0, left), behavior: "smooth" });
    }
    return index;
  }

  function stop() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    if (playing) {
      var button = playing.querySelector('[data-filmstrip-action="play"]');
      if (button) {
        button.textContent = "Play";
        button.setAttribute("aria-pressed", "false");
      }
    }
    playing = null;
  }

  function scheduleNext(strip) {
    if (!strip.isConnected) { stop(); return; }
    var list = frames(strip);
    var at = current(strip);
    if (at >= list.length - 1) { stop(); return; }
    var interval = Number(strip.dataset.intervalMs) || 2000;
    var ticks = Number(list[at + 1].dataset.tick) - Number(list[at].dataset.tick);
    timer = setTimeout(function () {
      if (!strip.isConnected) { stop(); return; }
      show(strip, at + 1);
      scheduleNext(strip);
    }, Math.max(1, ticks) * interval);
  }

  function play(strip, button) {
    if (playing === strip) { stop(); return; }
    stop();
    // From the end, play starts again from the beginning.
    if (current(strip) >= frames(strip).length - 1) show(strip, 0);
    playing = strip;
    button.textContent = "Pause";
    button.setAttribute("aria-pressed", "true");
    scheduleNext(strip);
  }

  document.addEventListener("click", function (event) {
    var strip = event.target.closest("[data-filmstrip]");
    if (!strip) return;

    var frame = event.target.closest("[data-filmstrip-frame]");
    if (frame) {
      // A plain click selects; a modified one opens the image as a link would.
      if (event.button !== 0 || event.ctrlKey || event.metaKey ||
          event.shiftKey || event.altKey) return;
      event.preventDefault();
      stop();
      show(strip, frames(strip).indexOf(frame));
      return;
    }

    var action = event.target.closest("[data-filmstrip-action]");
    if (!action) return;
    var kind = action.dataset.filmstripAction;
    if (kind === "play") {
      play(strip, action);
    } else if (kind === "prev") {
      stop();
      show(strip, current(strip) - 1);
    } else if (kind === "next") {
      stop();
      show(strip, current(strip) + 1);
    }
  });

  // Arrow keys and space, while focus is inside a strip.
  document.addEventListener("keydown", function (event) {
    var strip = event.target.closest && event.target.closest("[data-filmstrip]");
    if (!strip || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key === "ArrowLeft") {
      event.preventDefault(); stop(); show(strip, current(strip) - 1);
    } else if (event.key === "ArrowRight") {
      event.preventDefault(); stop(); show(strip, current(strip) + 1);
    } else if (event.key === " " && !event.target.closest("button")) {
      event.preventDefault();
      var button = strip.querySelector('[data-filmstrip-action="play"]');
      if (button) play(strip, button);
    }
  });
})();
