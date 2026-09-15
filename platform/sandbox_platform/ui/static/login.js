/* Signing in. Issue #38, DRAFT-061 decision 3.
 *
 * Fetch rather than a form POST, and not for convenience: `routers/auth.py`
 * defends CSRF by requiring the X-Sandbox-Request header, which is a complete
 * defence only while this application has no ordinary form POSTs. A cross-site
 * form cannot set a header; a cross-site fetch that tries is stopped by the
 * absent CORS middleware. Submitting this form the plain way would remove that
 * property for every route at once.
 *
 * An external file rather than inline, so a strict CSP needs no
 * 'unsafe-inline'.
 */

(function () {
    "use strict";

    var form = document.getElementById("login-form");
    if (!form) { return; }
    var result = document.getElementById("result");
    var totpRow = document.getElementById("totp-row");

    function say(text, danger) {
        result.innerHTML = "";
        var p = document.createElement("p");
        p.className = danger ? "note danger" : "note";
        /* textContent, never innerHTML: everything below can carry a
         * server-supplied reason, and this file is outside Jinja's
         * autoescaping. */
        p.textContent = text;
        result.appendChild(p);
    }

    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        say("Signing in...");

        var body = {
            email: document.getElementById("email").value,
            password: document.getElementById("password").value
        };
        var code = document.getElementById("totp").value.trim();
        if (code) { body.totp = code; }

        var r;
        try {
            r = await fetch("/api/v1/auth/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Sandbox-Request": "1"
                },
                body: JSON.stringify(body)
            });
        } catch (e) {
            say("Could not reach the server.", true);
            return;
        }

        if (r.status === 204) {
            /* The session is in two HttpOnly cookies, so there is nothing to
             * store here -- which is the point: a token this script could read
             * is a token an XSS could read. */
            window.location.assign("/ui/jobs");
            return;
        }

        var detail = "";
        try { detail = (await r.json()).detail || ""; } catch (e) { /* empty body */ }

        /* The server only mentions a second factor once the PASSWORD is right,
         * so revealing the field here discloses nothing a correct password
         * would not have. Asking everyone up front is what makes people think
         * the form is broken. */
        if (r.status === 401 && detail.indexOf("second-factor") !== -1) {
            totpRow.hidden = false;
            document.getElementById("totp").focus();
            say("Enter the code from your authenticator app.");
            return;
        }
        if (r.status === 429) {
            say("Too many attempts. Wait a minute and try again.", true);
            return;
        }
        say(detail || "Sign-in failed.", true);
    });
}());
