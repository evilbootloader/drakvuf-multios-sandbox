/* Signing out. Issue #38, DRAFT-061 decision 3.
 *
 * An external file rather than an inline handler, for the reason login.js
 * gives: inline script is what forces a CSP to carry 'unsafe-inline', and that
 * concession applies to the whole document rather than to the one line that
 * wanted it.
 *
 * Fetch rather than a form POST for the other reason login.js gives:
 * `routers/auth.py` defends CSRF by requiring the X-Sandbox-Request header,
 * which is a complete defence only while this application has no ordinary form
 * POSTs. A cross-site form cannot set a header; a cross-site fetch that tries
 * is stopped by the absent CORS middleware.
 */

(function () {
    "use strict";

    /* Absent on /ui/login, which shares this masthead. base.html renders
     * neither the button nor this script there -- offering "sign out" to
     * someone who is not signed in is a control that can only look broken --
     * so this guard is the second line rather than the first. */
    var btn = document.getElementById("sign-out");
    if (!btn) { return; }

    btn.addEventListener("click", async function () {
        btn.disabled = true;
        try {
            /* 204 whether or not there was a session: logout is idempotent, so
             * there is no failure here worth branching on. The route clears
             * both cookies and revokes every refresh token for the owner. */
            await fetch("/api/v1/auth/logout", {
                method: "POST",
                headers: { "X-Sandbox-Request": "1" }
            });
        } catch (e) {
            /* Swallowed on purpose. A network failure must still take the user
             * to the sign-in page: leaving them on a page that looks signed in
             * because the sign-out request did not land is the worse of the two
             * outcomes, and /ui/login is the one place that can tell them
             * whether they still have a session. */
        }
        window.location.assign("/ui/login");
    });
}());