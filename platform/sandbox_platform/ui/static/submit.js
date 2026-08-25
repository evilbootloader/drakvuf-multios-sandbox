/* The submission flow, in the browser. Issue #38.
 *
 * Four calls, and the order is the contract -- the same one submit.py walks
 * and is the reference for:
 *
 *   1. POST /api/v1/jobs            reserve a row, get a signed upload ticket
 *   2. POST <upload_url>            straight to the object store, NOT via us
 *   3. POST /api/v1/jobs/<id>/uploaded   admission runs here, server-side
 *   4. redirect to the job view
 *
 * Step 2 bypassing the API is the whole design: the platform never handles
 * sample bytes, because it is the one machine holding every credential. It is
 * also why this is JavaScript at all -- a plain <form> POST cannot do a
 * three-call sequence with a cross-service upload in the middle.
 *
 * An external file rather than inline, so a strict CSP needs no
 * 'unsafe-inline'.
 */

(function () {
    "use strict";

    var form = document.getElementById("submit-form");
    if (!form) { return; }
    var result = document.getElementById("result");

    function say(text, danger) {
        result.innerHTML = "";
        var p = document.createElement("p");
        p.className = danger ? "note danger" : "note";
        // textContent, never innerHTML. Everything below can carry a
        // server-supplied filename or reason, and this file is the one place
        // in the UI that Jinja's autoescaping does not cover.
        p.textContent = text;
        result.appendChild(p);
    }

    /* The honest names for the two rejections that are NORMAL rather than
     * broken. "submission failed" for either of these costs an operator an
     * hour working out which of two unrelated problems they have. */
    var REJECTION = {
        no_workers: "No analysis host has registered. Start sandboxd on Dom0.",
        no_capacity: "No registered host is large enough to run this job.",
        rejected_size: "The stored file did not match the size declared.",
        unreadable: "The uploaded object could not be read back.",
        unsupported_type: "That file type is not analysed on this target."
    };

    form.addEventListener("submit", async function (event) {
        event.preventDefault();

        var file = form.querySelector('input[type="file"]').files[0];
        var targetOs = form.querySelector('input[name="target_os"]:checked').value;
        if (!file) { say("Choose a file first.", true); return; }

        var button = form.querySelector('button[type="submit"]');
        button.disabled = true;

        try {
            say("Reserving a job…");
            var created = await post("/api/v1/jobs", {
                target_os: targetOs,
                filename: file.name,
                size_bytes: file.size
            });

            /* Fields BEFORE the file part: S3 stops reading at the file, so a
             * policy field after it is never seen. FormData preserves append
             * order, which is what makes this work. */
            say("Uploading " + file.name + "…");
            var body = new FormData();
            Object.keys(created.upload_fields).forEach(function (k) {
                body.append(k, created.upload_fields[k]);
            });
            body.append("file", file);

            var up;
            try {
                up = await fetch(created.upload_url, { method: "POST", body: body });
            } catch (netErr) {
                /* A cross-origin block surfaces here as a bare "Failed to
                 * fetch" with no detail -- the browser withholds it on
                 * purpose. That is the trap #37 exists to remove: the upload
                 * is same-origin in production precisely so this cannot
                 * happen, and if it does, the routing is wrong rather than
                 * the network. Say which, because "Failed to fetch" sends
                 * people looking at the wrong layer for an afternoon. */
                var target = new URL(created.upload_url).origin;
                throw new Error(
                    "Could not reach the object store at " + target + ". " +
                    (target === window.location.origin
                        ? "It did not respond."
                        : "It is on a different origin to this page, so the " +
                          "browser blocked the upload. The store should be " +
                          "path-routed on this hostname — see runbook step 26."));
            }
            if (!up.ok && up.status !== 204) {
                throw new Error("The object store refused the upload (" +
                                up.status + "). If the file is larger than " +
                                "declared, that is the size policy working.");
            }

            say("Admitting…");
            var job = await post("/api/v1/jobs/" + created.job_id + "/uploaded", null);

            if (job.state === "rejected") {
                say(REJECTION[job.failure_reason] || ("Rejected: " + job.failure_reason), true);
                button.disabled = false;
                return;
            }
            window.location = "/ui/jobs/" + created.job_id;
        } catch (err) {
            say(err.message || String(err), true);
            button.disabled = false;
        }
    });

    async function post(url, payload) {
        var init = { method: "POST", credentials: "same-origin" };
        if (payload !== null) {
            init.headers = { "Content-Type": "application/json" };
            init.body = JSON.stringify(payload);
        }
        var r = await fetch(url, init);
        var data = await r.json().catch(function () { return {}; });
        if (!r.ok) {
            /* FastAPI validation errors arrive as a list of objects; a
             * refused filename lands here, and the reason is worth showing
             * verbatim rather than flattening to "invalid". */
            var detail = data.detail;
            if (Array.isArray(detail)) {
                detail = detail.map(function (d) { return d.msg; }).join("; ");
            }
            throw new Error(detail || (r.status + " " + r.statusText));
        }
        return data;
    }
}());