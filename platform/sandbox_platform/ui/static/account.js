/* Enrolling and removing the second factor. DRAFT-061 decision 3.
 *
 * Fetch rather than form POSTs, for the reason login.js gives: the CSRF
 * defence is a required header, and that is complete only while this
 * application has no ordinary form POSTs.
 */

(function () {
    "use strict";

    var startBtn = document.getElementById("totp-start");
    if (!startBtn) { return; }

    var state = document.getElementById("totp-state");
    var enrolBox = document.getElementById("totp-enrol");
    var secretEl = document.getElementById("totp-secret");
    var secretRow = document.getElementById("totp-secret-row");
    var uriLink = document.getElementById("totp-uri");
    var confirmForm = document.getElementById("totp-confirm-form");
    var disableForm = document.getElementById("totp-disable-form");
    var recoveryBox = document.getElementById("recovery-box");
    var recoveryList = document.getElementById("recovery-list");
    var remainingEl = document.getElementById("recovery-remaining");
    var regenForm = document.getElementById("recovery-regen-form");
    var result = document.getElementById("result");

    /* Rendered as list items with textContent, never innerHTML. The codes are
     * server-generated hex so nothing here is hostile, but this file sits
     * outside Jinja's autoescaping and the habit is the protection. */
    function showCodes(codes) {
        recoveryList.innerHTML = "";
        codes.forEach(function (code) {
            var li = document.createElement("li");
            li.textContent = code;
            recoveryList.appendChild(li);
        });
        recoveryBox.hidden = false;
    }

    async function showRemaining() {
        var r = await fetch("/api/v1/auth/totp/recovery/remaining", {
            headers: { "X-Sandbox-Request": "1" }
        });
        if (!r.ok) { return; }
        var left = (await r.json()).remaining;
        remainingEl.textContent = left + " recovery code(s) remaining.";
        remainingEl.hidden = false;
        /* Running low is worth saying plainly: the moment someone needs one is
         * the moment they cannot get more. */
        remainingEl.className = left <= 2 ? "note danger" : "note";
    }

    function say(text, danger) {
        result.innerHTML = "";
        var p = document.createElement("p");
        p.className = danger ? "note danger" : "note";
        p.textContent = text;
        result.appendChild(p);
    }

    function post(path, body) {
        return fetch(path, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Sandbox-Request": "1"
            },
            body: JSON.stringify(body || {})
        });
    }

    async function detailOf(r) {
        try { return (await r.json()).detail || ""; } catch (e) { return ""; }
    }

    /* Show a freshly minted secret. The key is text rather than a QR image on
     * purpose -- see the template -- and the otpauth:// link is for the case
     * where the authenticator is on the SAME device, where a typed key is the
     * worst of both worlds.
     *
     * The scheme is checked before it reaches an href even though the server
     * builds it. An attribute that decides what a click executes should not
     * inherit its safety from a different file: `javascript:` in that slot is
     * script execution, and this is the one place on the page where a
     * server-supplied string becomes a URL rather than text. */
    function showSecret(body) {
        secretEl.textContent = body.secret;
        if (body.uri && body.uri.indexOf("otpauth://") === 0) {
            uriLink.href = body.uri;
            uriLink.hidden = false;
        } else {
            uriLink.removeAttribute("href");
            uriLink.hidden = true;
        }
        secretRow.hidden = false;
        enrolBox.hidden = false;
    }

    /* **A read, not a probe that mutates.** This used to POST /totp/enrol on
     * every page load and read the 409 as "MFA is on" -- which meant loading
     * the page while MFA was OFF overwrote any unconfirmed secret with a new
     * one. Add the key to your authenticator, reload (or have a second tab
     * open), and every code you type is checked against a secret the server
     * has already replaced, with nothing on the page to say so. */
    (async function show() {
        var r = await fetch("/api/v1/auth/totp/status", {
            headers: { "X-Sandbox-Request": "1" }
        });
        if (r.status === 401) {
            state.textContent = "Sign in to manage two-factor authentication.";
            return;
        }
        if (!r.ok) {
            state.textContent = "Could not read the current setting.";
            return;
        }

        var status = await r.json();
        if (status.enabled) {
            state.textContent = "Two-factor authentication is ON.";
            disableForm.hidden = false;
            regenForm.hidden = false;
            showRemaining();
            return;
        }
        if (!status.credentialed) {
            /* No credentials row, so there is nothing to attach a secret to
             * and the button below could only ever fail. */
            state.textContent = "This account has no password set, so there is"
                + " nothing to add a second factor to.";
            return;
        }

        state.textContent = "Two-factor authentication is OFF.";
        if (status.enrolling) {
            /* A secret exists and has not been confirmed. It is deliberately
             * NOT shown again: `/totp/status` returns no secret, so the only
             * copy is in whichever authenticator it was added to. The two
             * honest offers are therefore to finish with that authenticator,
             * or to press Start again -- which mints a new secret and throws
             * this one away. */
            say("Enrolment is already in progress. Enter the code from the"
                + " authenticator you added it to, or start again for a new"
                + " key.");
            enrolBox.hidden = false;
            startBtn.textContent = "Start again";
        }
        startBtn.hidden = false;
    }());

    /* **Minting is behind a press.** /totp/enrol replaces an unconfirmed
     * secret, so anything calling it without being asked destroys an enrolment
     * somebody may be halfway through. */
    startBtn.addEventListener("click", async function () {
        startBtn.disabled = true;
        var r = await post("/api/v1/auth/totp/enrol");
        startBtn.disabled = false;
        if (r.ok) {
            showSecret(await r.json());
            startBtn.textContent = "Start again";
            say("Add the key to your authenticator, then enter the code it"
                + " shows.");
            return;
        }
        say(await detailOf(r) || "Could not start enrolment.", true);
    });

    confirmForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        var r = await post("/api/v1/auth/totp/confirm", {
            code: document.getElementById("confirm-code").value.trim()
        });
        if (r.ok) {
            enrolBox.hidden = true;
            secretRow.hidden = true;
            /* The key is off the page the moment it is no longer needed, and
             * the button with it -- re-enrolling from here is refused by the
             * server now that the secret is confirmed. */
            secretEl.textContent = "";
            startBtn.hidden = true;
            disableForm.hidden = false;
            regenForm.hidden = false;
            state.textContent = "Two-factor authentication is ON.";
            showCodes((await r.json()).recovery_codes);
            showRemaining();
            say("Enabled. You will be asked for a code next time you sign in.");
            return;
        }
        say(await detailOf(r) || "That code was not accepted.", true);
    });

    disableForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        /* The password, not just a session: a session is exactly what an
         * attacker holding a stolen cookie has, and letting that remove the
         * second factor would make it worthless against the attack it exists
         * for. */
        var r = await post("/api/v1/auth/totp/disable", {
            password: document.getElementById("disable-password").value
        });
        if (r.status === 204) {
            disableForm.hidden = true;
            regenForm.hidden = true;
            recoveryBox.hidden = true;
            remainingEl.hidden = true;
            document.getElementById("disable-password").value = "";
            state.textContent = "Two-factor authentication is OFF.";
            /* Offered again straight away. Disabling is also what someone does
             * to REPLACE a lost authenticator, and a page that then has no way
             * back on is a page they have to know to reload. */
            startBtn.textContent = "Set up";
            startBtn.hidden = false;
            say("Turned off. The recovery codes were destroyed with it.");
            return;
        }
        if (r.status === 429) {
            say("Too many attempts. Wait a few minutes and try again.", true);
            return;
        }
        say(await detailOf(r) || "Could not turn it off.", true);
    });

    regenForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        /* The password again, not just a session: this hands back ten
         * credentials that each bypass the second factor. */
        var r = await post("/api/v1/auth/totp/recovery", {
            password: document.getElementById("regen-password").value
        });
        if (r.ok) {
            document.getElementById("regen-password").value = "";
            showCodes((await r.json()).recovery_codes);
            showRemaining();
            say("Replaced. The previous codes no longer work.");
            return;
        }
        /* Both password routes are rate limited and share one bucket with the
         * account lockout, so a run of wrong passwords stops answering rather
         * than answering "incorrect" forever. Saying which it was beats a 401
         * the user reads as "my password changed". */
        if (r.status === 429) {
            say("Too many attempts. Wait a few minutes and try again.", true);
            return;
        }
        say(await detailOf(r) || "Could not replace them.", true);
    });
}());
