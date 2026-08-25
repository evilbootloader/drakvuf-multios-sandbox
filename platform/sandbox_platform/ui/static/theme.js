/* Light/dark toggle. Issue #38.
 *
 * Loaded in <head> WITHOUT defer, deliberately. The stored choice has to be
 * applied before the first paint, or a dark-mode user gets a white flash on
 * every navigation. An inline script would do the same job and would need
 * 'unsafe-inline' in the CSP, which is not a trade worth making for this.
 */

(function () {
    "use strict";

    var KEY = "sandbox-theme";

    /* Three states, not two. "system" is the default and is NOT the same as
     * whichever of light/dark the system currently is -- it follows the
     * system when the system changes, which an explicit choice must not. */
    function apply(theme) {
        if (theme === "light" || theme === "dark") {
            document.documentElement.setAttribute("data-theme", theme);
        } else {
            document.documentElement.removeAttribute("data-theme");
        }
    }

    var stored = null;
    try { stored = localStorage.getItem(KEY); } catch (e) { /* private mode */ }
    apply(stored);

    document.addEventListener("DOMContentLoaded", function () {
        var button = document.getElementById("theme-toggle");
        if (!button) { return; }

        function label() {
            var current = document.documentElement.getAttribute("data-theme");
            button.textContent = current === "light" ? "light"
                               : current === "dark" ? "dark"
                               : "auto";
            button.title = "Theme: " + button.textContent + " — click to change";
        }

        button.addEventListener("click", function () {
            var current = document.documentElement.getAttribute("data-theme");
            var next = current === "dark" ? "light"
                     : current === "light" ? null
                     : "dark";
            apply(next);
            try {
                if (next) { localStorage.setItem(KEY, next); }
                else { localStorage.removeItem(KEY); }
            } catch (e) { /* choice is not persisted; the page still works */ }
            label();
        });

        label();
    });
}());
