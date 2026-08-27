# Verifying `sandboxd`, the platform API, the web UI and the live console

> **Status: written 2026-08-26, NOT YET EXECUTED.** Every `EVIDENCE` block is
> empty and stays empty until an operator pastes real output into it. Per this
> project's convention a runbook is committed *after* execution, so if you are
> reading this in git history with the blocks still empty, it was committed
> early by mistake.
>
> **Nothing in `sandboxd` has ever run against a real `xl`, `lvcreate`,
> `injector` or `drakvuf`.** 252 tests pass against a recording fake, which is
> what makes booking Dom0 time worth it — not a substitute for having done it.

## What this covers, and in what order

| Part | Where | Why this order |
|---|---|---|
| A | platform | The API and UI are verifiable alone; do them first so a failure later is not ambiguous |
| B | Dom0 | Settle the two **unverified** questions before running anything |
| C | Dom0 + platform | One real analysis, end to end |
| D | both | The live console |
| E | platform | The properties that must survive all of it |

Two things are **Candidate** per CLAUDE.md and are settled in Part B before
anything depends on them: how `drakvuf -a` treats plugins, and how to find a
clone's VNC port.

---

# Part A — the platform, on its own

## A1. Deploy the current build

Nine-plus commits are pending as of writing, including the tab-underline fix
the deployment is missing.

```bash
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c 'cd /opt/platform/src && git pull --ff-only'
pct exec 102 -- su - platform -s /bin/bash -c 'cd /opt/platform/src/platform && .venv/bin/python migrations/run.py'
pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser
pct exec 102 -- systemctl --no-pager status sandbox-api | head -20
remote: Enumerating objects: 238, done.
remote: Counting objects: 100% (238/238), done.
remote: Compressing objects: 100% (130/130), done.
remote: Total 204 (delta 72), reused 204 (delta 72), pack-reused 0 (from 0)
Receiving objects: 100% (204/204), 344.81 KiB | 1.33 MiB/s, done.
Resolving deltas: 100% (72/72), completed with 25 local objects.
From github.com:evilbootloader/drakvuf-multios-sandbox
   ad855cb..329df81  master     -> origin/master
Updating ad855cb..329df81
Fast-forward
 .github/issue-drafts/DRAFT-018.md                           |  474 ++++
 .github/issue-drafts/DRAFT-019.md                           |   12 +-
 .github/issue-drafts/DRAFT-048.md                           |   10 +
 .github/issue-drafts/DRAFT-049.md                           |   10 +
 .github/issue-drafts/DRAFT-051.md                           |   10 +
 .github/issue-drafts/DRAFT-060.md                           |   97 +-
 .github/issue-drafts/issue-index.md                         |    2 +-
 docs/architecture/analysis-pipeline.md                      |   19 +-
 docs/architecture/live-console.md                           |  395 +++
 docs/architecture/platform.md                               |   12 +-
 docs/architecture/result-schema.md                          |  168 +-
 platform/fake_worker.py                                     |   35 +-
 platform/migrations/0005_console.sql                        |   35 +
 platform/sandbox_platform/app.py                            |    6 +
 platform/sandbox_platform/config.py                         |   31 +
 platform/sandbox_platform/console.py                        |  213 ++
 platform/sandbox_platform/manifest.py                       |  374 +++
 platform/sandbox_platform/objects.py                        |    8 +
 platform/sandbox_platform/routers/console.py                |  201 ++
 platform/sandbox_platform/routers/jobs.py                   |   82 +-
 platform/sandbox_platform/routers/worker.py                 |  100 +-
 platform/sandbox_platform/ui/__init__.py                    |   54 +-
 platform/sandbox_platform/ui/static/VENDOR.md               |   73 +-
 platform/sandbox_platform/ui/static/app.css                 |   30 +-
 platform/sandbox_platform/ui/static/console.js              |   93 +
 platform/sandbox_platform/ui/static/job.js                  |   94 +
 platform/sandbox_platform/ui/static/novnc/LICENSE.txt       |   62 +
 platform/sandbox_platform/ui/static/novnc/core/base64.js    |  104 +
 .../sandbox_platform/ui/static/novnc/core/crypto/aes.js     |  178 ++
 .../sandbox_platform/ui/static/novnc/core/crypto/bigint.js  |   34 +
 .../sandbox_platform/ui/static/novnc/core/crypto/crypto.js  |   90 +
 .../sandbox_platform/ui/static/novnc/core/crypto/des.js     |  330 +++
 platform/sandbox_platform/ui/static/novnc/core/crypto/dh.js |   55 +
 .../sandbox_platform/ui/static/novnc/core/crypto/md5.js     |   82 +
 .../sandbox_platform/ui/static/novnc/core/crypto/rsa.js     |  132 +
 .../ui/static/novnc/core/decoders/copyrect.js               |   27 +
 .../sandbox_platform/ui/static/novnc/core/decoders/h264.js  |  321 +++
 .../ui/static/novnc/core/decoders/hextile.js                |  181 ++
 .../sandbox_platform/ui/static/novnc/core/decoders/jpeg.js  |  146 +
 .../sandbox_platform/ui/static/novnc/core/decoders/raw.js   |   59 +
 .../sandbox_platform/ui/static/novnc/core/decoders/rre.js   |   44 +
 .../sandbox_platform/ui/static/novnc/core/decoders/tight.js |  393 +++
 .../ui/static/novnc/core/decoders/tightpng.js               |   27 +
 .../sandbox_platform/ui/static/novnc/core/decoders/zlib.js  |   51 +
 .../sandbox_platform/ui/static/novnc/core/decoders/zrle.js  |  185 ++
 platform/sandbox_platform/ui/static/novnc/core/deflator.js  |   84 +
 platform/sandbox_platform/ui/static/novnc/core/display.js   |  575 ++++
 platform/sandbox_platform/ui/static/novnc/core/encodings.js |   54 +
 platform/sandbox_platform/ui/static/novnc/core/inflator.js  |   65 +
 .../ui/static/novnc/core/input/domkeytable.js               |  311 +++
 .../ui/static/novnc/core/input/fixedkeys.js                 |  129 +
 .../ui/static/novnc/core/input/gesturehandler.js            |  567 ++++
 .../sandbox_platform/ui/static/novnc/core/input/keyboard.js |  294 ++
 .../sandbox_platform/ui/static/novnc/core/input/keysym.js   |  616 +++++
 .../ui/static/novnc/core/input/keysymdef.js                 |  688 +++++
 .../sandbox_platform/ui/static/novnc/core/input/util.js     |  191 ++
 .../sandbox_platform/ui/static/novnc/core/input/vkeys.js    |  116 +
 .../ui/static/novnc/core/input/xtscancodes.js               |  173 ++
 platform/sandbox_platform/ui/static/novnc/core/ra2.js       |  312 +++
 platform/sandbox_platform/ui/static/novnc/core/rfb.js       | 3415 ++++++++++++++++++++++++
 .../sandbox_platform/ui/static/novnc/core/util/browser.js   |  233 ++
 .../sandbox_platform/ui/static/novnc/core/util/cursor.js    |  249 ++
 .../sandbox_platform/ui/static/novnc/core/util/element.js   |   32 +
 .../sandbox_platform/ui/static/novnc/core/util/events.js    |  138 +
 .../ui/static/novnc/core/util/eventtarget.js                |   35 +
 platform/sandbox_platform/ui/static/novnc/core/util/int.js  |   15 +
 .../sandbox_platform/ui/static/novnc/core/util/logging.js   |   56 +
 .../sandbox_platform/ui/static/novnc/core/util/strings.js   |   28 +
 platform/sandbox_platform/ui/static/novnc/core/websock.js   |  365 +++
 .../sandbox_platform/ui/static/novnc/vendor/pako/LICENSE    |   21 +
 .../sandbox_platform/ui/static/novnc/vendor/pako/README.md  |    6 +
 .../ui/static/novnc/vendor/pako/lib/utils/common.js         |   45 +
 .../ui/static/novnc/vendor/pako/lib/zlib/adler32.js         |   27 +
 .../ui/static/novnc/vendor/pako/lib/zlib/constants.js       |   47 +
 .../ui/static/novnc/vendor/pako/lib/zlib/crc32.js           |   36 +
 .../ui/static/novnc/vendor/pako/lib/zlib/deflate.js         | 1846 +++++++++++++
 .../ui/static/novnc/vendor/pako/lib/zlib/gzheader.js        |   35 +
 .../ui/static/novnc/vendor/pako/lib/zlib/inffast.js         |  324 +++
 .../ui/static/novnc/vendor/pako/lib/zlib/inflate.js         | 1527 +++++++++++
 .../ui/static/novnc/vendor/pako/lib/zlib/inftrees.js        |  322 +++
 .../ui/static/novnc/vendor/pako/lib/zlib/messages.js        |   11 +
 .../ui/static/novnc/vendor/pako/lib/zlib/trees.js           | 1195 +++++++++
 .../ui/static/novnc/vendor/pako/lib/zlib/zstream.js         |   24 +
 platform/sandbox_platform/ui/templates/_job_live.html       |   20 +
 platform/sandbox_platform/ui/templates/_job_status.html     |   98 +
 platform/sandbox_platform/ui/templates/_job_tabs.html       |   35 +
 platform/sandbox_platform/ui/templates/job.html             |   64 +-
 platform/tests/test_console.py                              |  229 ++
 platform/tests/test_manifest.py                             |  408 +++
 platform/tests/test_ui_browser.py                           |  177 ++
 platform/tests/test_worker_api.py                           |   18 +-
 sandboxd/__init__.py                                        |    0
 sandboxd/api.py                                             |  348 +++
 sandboxd/clone.py                                           |  452 ++++
 sandboxd/daemon.py                                          |  400 +++
 sandboxd/guests.py                                          |  433 +++
 sandboxd/naming.py                                          |   98 +
 sandboxd/proc.py                                            |  410 +++
 sandboxd/resources.py                                       |  322 +++
 sandboxd/runner.py                                          |   67 +
 sandboxd/stages.py                                          |  522 ++++
 sandboxd/sweep.py                                           |  276 ++
 sandboxd/tests/__init__.py                                  |    0
 sandboxd/tests/fake.py                                      |  170 ++
 sandboxd/tests/test_api.py                                  |  339 +++
 sandboxd/tests/test_clone.py                                |  343 +++
 sandboxd/tests/test_concurrency.py                          |  419 +++
 sandboxd/tests/test_daemon.py                               |  451 ++++
 sandboxd/tests/test_guests.py                               |  408 +++
 sandboxd/tests/test_proc.py                                 |  319 +++
 sandboxd/tests/test_resources.py                            |  417 +++
 sandboxd/tests/test_stages.py                               |  437 +++
 sandboxd/tests/test_sweep.py                                |  310 +++
 sandboxd/tests/test_timing.py                               |  130 +
 sandboxd/tests/test_vnc.py                                  |  115 +
 sandboxd/timing.py                                          |  187 ++
 sandboxd/tls.py                                             |   51 +
 sandboxd/vnc.py                                             |  173 ++
 118 files changed, 27800 insertions(+), 192 deletions(-)
 create mode 100644 .github/issue-drafts/DRAFT-018.md
 create mode 100644 docs/architecture/live-console.md
 create mode 100644 platform/migrations/0005_console.sql
 create mode 100644 platform/sandbox_platform/console.py
 create mode 100644 platform/sandbox_platform/manifest.py
 create mode 100644 platform/sandbox_platform/routers/console.py
 create mode 100644 platform/sandbox_platform/ui/static/console.js
 create mode 100644 platform/sandbox_platform/ui/static/job.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/LICENSE.txt
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/base64.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/crypto/aes.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/crypto/bigint.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/crypto/crypto.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/crypto/des.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/crypto/dh.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/crypto/md5.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/crypto/rsa.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/copyrect.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/h264.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/hextile.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/jpeg.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/raw.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/rre.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/tight.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/tightpng.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/zlib.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/decoders/zrle.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/deflator.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/display.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/encodings.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/inflator.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/domkeytable.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/fixedkeys.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/gesturehandler.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/keyboard.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/keysym.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/keysymdef.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/util.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/vkeys.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/input/xtscancodes.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/ra2.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/rfb.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/browser.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/cursor.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/element.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/events.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/eventtarget.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/int.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/logging.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/util/strings.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/core/websock.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/LICENSE
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/README.md
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/utils/common.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/adler32.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/constants.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/crc32.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/deflate.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/gzheader.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/inffast.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/inflate.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/inftrees.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/messages.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/trees.js
 create mode 100644 platform/sandbox_platform/ui/static/novnc/vendor/pako/lib/zlib/zstream.js
 create mode 100644 platform/sandbox_platform/ui/templates/_job_live.html
 create mode 100644 platform/sandbox_platform/ui/templates/_job_status.html
 create mode 100644 platform/sandbox_platform/ui/templates/_job_tabs.html
 create mode 100644 platform/tests/test_console.py
 create mode 100644 platform/tests/test_manifest.py
 create mode 100644 sandboxd/__init__.py
 create mode 100644 sandboxd/api.py
 create mode 100644 sandboxd/clone.py
 create mode 100644 sandboxd/daemon.py
 create mode 100644 sandboxd/guests.py
 create mode 100644 sandboxd/naming.py
 create mode 100644 sandboxd/proc.py
 create mode 100644 sandboxd/resources.py
 create mode 100644 sandboxd/runner.py
 create mode 100644 sandboxd/stages.py
 create mode 100644 sandboxd/sweep.py
 create mode 100644 sandboxd/tests/__init__.py
 create mode 100644 sandboxd/tests/fake.py
 create mode 100644 sandboxd/tests/test_api.py
 create mode 100644 sandboxd/tests/test_clone.py
 create mode 100644 sandboxd/tests/test_concurrency.py
 create mode 100644 sandboxd/tests/test_daemon.py
 create mode 100644 sandboxd/tests/test_guests.py
 create mode 100644 sandboxd/tests/test_proc.py
 create mode 100644 sandboxd/tests/test_resources.py
 create mode 100644 sandboxd/tests/test_stages.py
 create mode 100644 sandboxd/tests/test_sweep.py
 create mode 100644 sandboxd/tests/test_timing.py
 create mode 100644 sandboxd/tests/test_vnc.py
 create mode 100644 sandboxd/timing.py
 create mode 100644 sandboxd/tls.py
 create mode 100644 sandboxd/vnc.py
DATABASE_URL is not set
● sandbox-api.service - DRAKVUF sandbox platform API
     Loaded: loaded (/etc/systemd/system/sandbox-api.service; enabled; preset: enabled)
     Active: active (running) since Wed 2026-08-26 19:24:50 UTC; 370ms ago
 Invocation: 5cfdb93d11be406bbcc6718332dc4b32
   Main PID: 2653 (python)
      Tasks: 1 (limit: 34766)
     Memory: 46.9M (peak: 46.9M)
        CPU: 342ms
     CGroup: /system.slice/sandbox-api.service
             └─2653 /opt/platform/src/platform/.venv/bin/python -m uvicorn sandbox_platform.app:app --host 192.168.1.10 --port 8443 --ssl-certfile /etc/sandbox-platform/tls/api.crt --ssl-keyfile /etc/sandbox-platform/tls/api.key --ssl-ca-certs /etc/sandbox-platform/tls/ca.crt --ssl-cert-reqs 2

Aug 26 19:24:50 platform systemd[1]: Started sandbox-api.service - DRAKVUF sandbox platform API.
```

> **F1 — the migration did not apply.** `DATABASE_URL is not set`, and the step
> above is wrong: `su - platform` is a **login shell**, so it inherits none of
> the environment the systemd unit supplies. The runner refused rather than
> falling back to a default, which is the behaviour it was given deliberately
> — but the pull and the restart both succeeded, so the API came up running
> code that reads columns the schema does not have yet.
>
> **`GET /api/v1/jobs/<id>` and the job page will 500 until A1b runs**, because
> `_detail` selects `*` and then reads `row["interacted"]`.

## A1b. Apply the migration, with the environment the service uses

Both services read `/etc/sandbox-platform/api.env` (`deploy-platform-lxc.md`
:1463), so sourcing it is what makes a command run by hand see what the service
sees. `set -a` exports everything the file defines rather than needing each
line to say `export`. This is the form already proven at
`deploy-platform-lxc.md:1602`.

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  set -a; . /etc/sandbox-platform/api.env; set +a
  .venv/bin/python migrations/run.py --status
  .venv/bin/python migrations/run.py
  .venv/bin/python migrations/run.py --status
'
pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser
```

`--status` before *and* after, so what was pending and what applied are both on
the record rather than inferred. Running it twice would also be safe — the
runner is idempotent and checksum-guarded, so a migration edited after being
applied fails loudly instead of silently diverging.

```text
root@pve1:~# pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src/platform
  set -a; . /etc/sandbox-platform/api.env; set +a
  .venv/bin/python migrations/run.py --status
  .venv/bin/python migrations/run.py
  .venv/bin/python migrations/run.py --status
'
pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser
 applied  0001_jobs.sql
 applied  0002_triggers.sql
 applied  0003_sample_etag.sql
 applied  0004_results_bytes.sql
 pending  0005_console.sql
applied  0005_console.sql
 applied  0001_jobs.sql
 applied  0002_triggers.sql
 applied  0003_sample_etag.sql
 applied  0004_results_bytes.sql
 applied  0005_console.sql
```

## A2. The API answers, and the schema took the new columns

> **F2 — the first version of this step was wrong twice.** It used
> `http://127.0.0.1:9000` and got *"Client sent an HTTP request to an HTTPS
> server"*. **9000 is MinIO**, not the API, and it is TLS on this deployment
> (#39) — so the error was about the wrong service AND the wrong scheme. The
> step also carried a stray `""")`, debris from a bad edit that would have gone
> straight into a shell.
>
> Worth noting what this rules out: it is not evidence the API is down. It is
> evidence the check was pointed at the object store.

Two listeners, two different proofs of identity
(`deploy-platform-lxc.md:1422`):

| Port | Who | Auth |
|---|---|---|
| `192.168.1.10:8443` | Dom0 / the worker channel | mutual TLS — a client certificate |
| `192.168.1.10:8000` | `cloudflared`, then the browser | Access at the edge |

```bash
# The browser listener. --insecure because the CA is ours and the container
# does not trust it by default; this is checking that the service answers,
# not that TLS is right -- deploy-platform-lxc.md step 5 does that.
pct exec 102 -- curl -sk https://192.168.1.10:8000/healthz; echo

# The mTLS listener needs a client certificate, so it is checked from Dom0
# rather than from inside the container:
#   curl --cacert ca.crt --cert dom0.crt --key dom0.key \
#        https://192.168.1.10:8443/healthz
```

The schema, via `information_schema` rather than `\d`:

```bash
pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -Atc \
  "SELECT column_name, data_type, column_default FROM information_schema.columns WHERE table_name = 'jobs' AND column_name IN ('console_requested','interacted') ORDER BY column_name"
```

> **`runuser`, not `su -c`, and that is what makes the quoting survivable.**
> `pct exec` passes argv, `runuser -u platform --` passes argv, and psql
> receives the SQL as one argument — so **no shell ever parses it**. With
> `su - platform -s /bin/bash -c "..."` there is an extra shell in the middle
> that eats a level of quoting, which is what mangled the first version of this
> step.
>
> `information_schema` rather than `\d` for the same reason: `\d` is a psql
> meta-command whose backslash has to survive every layer, where this is a
> plain query.

Expect exactly two rows, both `boolean` defaulting to `false`:

```text
console_requested|boolean|false
interacted|boolean|false
```

**No rows means A1b did not run.** Go back and apply the migration before
anything else — the API is reading columns that do not exist.

```text
root@pve1:~# pct exec 102 -- curl -sk https://192.168.1.10:8000/healthz; echo
{"status":"ok"}
root@pve1:~# pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -Atc \
  "SELECT column_name, data_type, column_default FROM information_schema.columns WHERE table_name = 'jobs' AND column_name IN ('console_requested','interacted') ORDER BY column_name"
console_requested|boolean|false
interacted|boolean|false

```

## A3. The UI, in a browser

Open `https://sandbox.evilbootloader.com/` — it should land on `/ui`.

Check each, and note anything that does not match:

- [x] The root redirects to the UI rather than 404ing
- [x] **Clicking a tab moves the red underline.** This is the fix the
      deployment was missing; if it still does not move after A1, the pull did
      not take
- [x] Search with every filter on "any" returns results rather than a 422
- [x] The theme button cycles auto → dark → light and the choice survives
      navigation

```text
Everything worked
```

---

# Part B — the two unverified questions

**Do this before Part C.** Both are marked Candidate in the source and both
change what the rest means.

## B1. Is `drakvuf -a` restrictive or additive?

This decides whether `hidsim` has been running in every trace this project has
ever produced. With no `--hid-template`, hidsim moves the mouse **randomly** —
guest activity that no report attributes to anything, and which would make a
sample that appears to open a file indistinguishable from one that chose to.

```bash
# On Dom0. Capture the WHOLE help this time -- the existing capture in
# verify-user-placeholder.md was grep-filtered and lost this line.
drakvuf --help 2>&1 | tee /tmp/drakvuf-help-full.txt
grep -nE -- '^\s+-a|--activate|plugin' /tmp/drakvuf-help-full.txt | head -20

# And the authoritative answer, if the pinned checkout is on this host:
grep -rn "plugin_list\|enable_plugin\|-a," /path/to/drakvuf/src/main.cpp | head -20
```

Then the behavioural check, which beats reading either:

```bash
# Trace something trivial with our four plugins and see whether hidsim
# announces itself. Run against a THROWAWAY clone, not a real analysis.
drakvuf -r profiles/linux.json -d 1 -i 1415     -a syscalls -o json -t 100 2>&1 > /tmp/drakvuf.out
grep -nE -- '^\s+-a|--activate|plugin' /tmp/drakvuf-help-full.txt | head -20
grep -i "hid" /tmp/drakvuf.out | head -20 
```

```text
root@drakvuf:~/drakvuf-multios-sandbox# grep -nE -- '^\s+-a|--activate|plugin' /tmp/drakvuf-help-full.txt | head -20
32:	 -x <plugin>               Don't activate the specified plugin
33:	 --wait-stop-plugins <timeout>
34:	                           Wait for plugins to stop before termination loop
35:	 -a <plugin>               Activate the specified plugin
55:	                           File with list of syscalls for trap in syscalls plugin (trap all if parameter is absent)
61:	                           Prevent bsodmon from stopping with other plugins
root@drakvuf:~/drakvuf-multios-sandbox# grep -rn "plugin_list\|enable_plugin\|-a," /path/to/drakvuf/src/main.cpp | head -20
grep: /path/to/drakvuf/src/main.cpp: No such file or directory
root@drakvuf:~/drakvuf-multios-sandbox# grep -rn "plugin_list\|enable_plugin\|-a," /home/user/drakvuf/src/main.cpp | head -20
143:static inline bool disable_plugin(char* _optarg, bool* plugin_list)
149:            plugin_list[i] = false;
157:static inline void disable_all_plugins(bool* plugin_list)
160:        plugin_list[i] = false;
163:static inline bool enable_plugin(char* _optarg, bool* plugin_list, bool* disabled_all)
167:        disable_all_plugins(plugin_list);
174:            plugin_list[i] = true;
438:    bool plugin_list[] = {[0 ... __DRAKVUF_PLUGIN_LIST_MAX-1] = 1};
733:                if (!disable_plugin(optarg, plugin_list))
744:                if (!enable_plugin(optarg, plugin_list, &disabled_all))
1205:    if (drakvuf->start_plugins(plugin_list, &options) < 0)
1236:        plugin_list[PLUGIN_BSODMON] = false;
1239:    int rc = drakvuf->stop_plugins(plugin_list);
1246:        drakvuf->plugin_stop_loop(wait_stop_plugins_timeout, plugin_list);

oot@drakvuf:~/drakvuf-multios-sandbox# ./automation/clone.pl ubuntu_sandbox 1 misc/ubuntu_sandbox.cfg 
1root@drakvuf:~/drakvuf-multios-sandbox# 
root@drakvuf:~/drakvuf-multios-sandbox# drakvuf -r profiles/linux.json -d 1 -i 1415     -a syscalls -o json -t 100 2>&1 > /tmp/drakvuf.out 
1787773416.003095 DRAKVUF v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
[SYSCALLS] Syscall table breakpoints set
[SYSCALLS] linux_cb fired (count=1) trap=do_syscall_64 rdi=0xffffb3ccc0f77f58 rsi=0xdb
[SYSCALLS] linux_cb fired (count=2) trap=restart_syscall rdi=0xffffb3ccc17dff58 rsi=0x10f
[SYSCALLS] linux_cb fired (count=3) trap=ppoll rdi=0xffffb3ccc0bc7f58 rsi=0xdb
root@drakvuf:~/drakvuf-multios-sandbox# grep -i "hid" /tmp/drakvuf.out | head -20 
{"Plugin":"syscall","TimeStamp":"1787773501.232386","PID":1596,"PPID":1,"TID":1596,"UserId":0,"ProcessName":"/usr/lib/apt/apt-helper","Method":"openat","EventUID":"0xfac7","ThreadName":"apt-helper","Module":"linux","vCPU":0,"CR3":"0x4f00000","Syscall":257,"NArgs":4,"Type":"x64","dirfd":"0xffffff9c","pathname":"/etc/apt/apt.conf.d/60icons-hidpi","flags":"0x80100","mode":"0x21614f5b"}
```

### RESULT — restrictive. `hidsim` has never run.

Answered from the source rather than from behaviour, which is the stronger
form: `/home/user/drakvuf/src/main.cpp`.

```c
438:  bool plugin_list[] = {[0 ... __DRAKVUF_PLUGIN_LIST_MAX-1] = 1};
163:  static inline bool enable_plugin(char* _optarg, bool* plugin_list,
                                       bool* disabled_all)
167:          disable_all_plugins(plugin_list);
174:          plugin_list[i] = true;
```

Every plugin starts enabled (`:438`) — but the **first `-a` calls
`disable_all_plugins()`** and only then enables what it names. So `-a` is
**restrictive**, and the four plugins the pipeline passes are the only four
that have ever run.

The `grep -i hid` above is consistent: its single hit is a syscall event whose
`pathname` happens to contain `60icons-hidpi`, not a `[HIDSIM]` line. There is
no hidsim output because there was no hidsim.

**Nothing to reconcile.** No Ubuntu or Android trace in this project contains
synthetic mouse input, an operator driving the DRAFT-056 console is not
competing with a synthetic pointer, and DRAFT-055 starts from zero as its own
draft assumes. Recorded in `docs/architecture/upstream-drakvuf.md` and
`docs/architecture/live-console.md` §4.6, which is now closed.

Noted in passing, for DRAFT-052: `-x` / `disable_plugin` exists
(`main.cpp:143,733`), so a plugin can be excluded without re-listing the rest.

## B2. How is a clone's VNC port found?

Both readings in `sandboxd/vnc.py` are guesses.

```bash
# With a clone running (Part C creates one; or build one by hand first):
xenstore-read /local/domain/<domid>/console/vnc-port
xl list -l <clone-domain> | grep -iA3 vnc
ss -ltnp | grep 59            # what QEMU actually bound, and to which address
```

The third command is the one that matters most: it shows whether the console is
on `127.0.0.1` as every `misc/*.cfg` says. **If it is bound to anything else,
stop** — the whole live-console design assumes loopback and a wider binding is
a containment problem regardless of this feature.

```text
root@drakvuf:~/drakvuf-multios-sandbox# ./automation/clone.pl ubuntu_sandbox 1 misc/ubuntu_sandbox.cfg 
2root@drakvuf:~/drakvuf-multios-sandbox# 
root@drakvuf:~/drakvuf-multios-sandbox# xenstore-read /local/domain/2/console/vnc-port
5900
root@drakvuf:~/drakvuf-multios-sandbox# xl list -l 2 | grep -iA3 vnc
                    "vnc": {
                        "enable": "True",
                        "listen": "127.0.0.1"
                    },
root@drakvuf:~/drakvuf-multios-sandbox# ss -ltnp | grep 59            # what QEMU actually bound, and to which address
LISTEN 0      1          127.0.0.1:5900      0.0.0.0:*    users:(("qemu-system-i38",pid=3256,fd=37))
```

---

# Part C — one real analysis, end to end

## C1. Install and configure `sandboxd`

```bash
# On Dom0, in the checkout.
cd /root/drakvuf-multios-sandbox && git pull --ff-only
python3 -c 'import sys; print(sys.version)'      # 3.8+ is what sandboxd targets
```

`sandboxd` needs these, and there is deliberately **no default for capacity** —
guessing how much memory Dom0 may give clones is how a host overcommits:

```bash
export SANDBOXD_API=https://192.168.1.10:8443   # the mTLS worker channel
export WORKER_TOKEN=<the same token the platform has>
export SANDBOXD_TOTAL_MIB=<measure it: free -m, minus what Dom0 needs>
export SANDBOXD_MAX_CLONES=2
# The console dials the BROWSER listener, not the worker one. The platform runs
# two uvicorn processes over the same app and the relay pairs sockets in an
# in-process registry, so both ends of a session must reach the SAME one (F11).
SANDBOXD_CONSOLE_API=https://192.168.1.10:8000         # MUST match network-setup.sh's argument
export SANDBOXD_CACERT=/root/ca.crt
export SANDBOXD_CLIENT_CERT=/root/dom0.crt
export SANDBOXD_CLIENT_KEY=/root/dom0.key
```

> **8443, not 9000.** 9000 is MinIO, which is also TLS on this deployment —
> pointing `sandboxd` there produces a TLS error that looks like a certificate
> problem rather than a wrong port. 8443 is the listener that demands a client
> certificate (`--ssl-cert-reqs 2`), which is what the `SANDBOXD_CLIENT_CERT`
> and `SANDBOXD_CLIENT_KEY` above are for.

> `SANDBOXD_MAX_CLONES` and `network-setup.sh`'s argument size the same thing
> from two sides — the VLAN pool and the `xenbr1.<n>` sub-interfaces. Raise one
> without the other and a clone gets a VLAN with no gateway, which reads as a
> sample that chose not to talk.

## C2. **Stop `dirwatch` first**

```bash
pgrep -a dirwatch
# If anything is running, stop it. sandboxd refuses to start otherwise.
```

Migration is a cutover, not coexistence: both allocate VLANs from low numbers
with no shared state, so they would collide on gateway addresses and isolation
rules with no symptom but interference between two malware analyses.

## C3. Dependencies, credentials, then start it

### C3a. The one library

`sandboxd` is stdlib plus **`httpx`** and nothing else — checked by reading
every import in `sandboxd/*.py`, not assumed.

```bash
# On Dom0, as root, in the checkout.
cd /root/drakvuf-multios-sandbox
apt-get install -y python3-venv          # if not already present
python3 -m venv .venv-sandboxd
.venv-sandboxd/bin/pip install httpx 'websockets==16.1.1'
.venv-sandboxd/bin/python -c "
import httpx, websockets
print('httpx', httpx.__version__, '| websockets', websockets.__version__)"
```

> A venv rather than `pip install --break-system-packages`: Dom0 is the machine
> that runs malware and its system Python is used by Xen's own tooling. One
> directory that can be deleted is a smaller commitment than a package
> installed system-wide.

> **`websockets`, not `httpx-ws`, and the reason is layering rather than
> trust.** httpx-ws would reuse the existing httpx client so the SSL context
> with Dom0's client certificate carries for free — but it does not implement
> the protocol, it adapts `wsproto` onto httpx. That is two libraries where one
> will do, one of them pre-1.0 (`Development Status :: 4 - Beta`), on the path
> between the internet and the machine running malware.
>
> `websockets` takes the same `SSLContext` object directly, so the advantage
> disappears — and it is already what the platform's uvicorn uses to accept the
> browser's end, so one implementation serves both sides.

### C3b. Certificates — three files, from the CA that already exists

Dom0 presents a client certificate because the worker listener runs with
`--ssl-cert-reqs 2`. The identity is **`dom0-lab`**, issued at
`deploy-platform-lxc.md:830` with `./tls/issue-cert.sh client dom0-lab`, and
that runbook is explicit: *"`dom0-lab.crt`/`dom0-lab.key` go to Dom0 and
nowhere else."*

| File | What it is | Where it comes from |
|---|---|---|
| `ca.crt` | the internal CA's certificate | the offline CA vault |
| `dom0-lab.crt` | Dom0's identity | `issue-cert.sh client dom0-lab` |
| `dom0-lab.key` | its private key | same |

**The CA root key must never reach Dom0** — only the CA *certificate*. It is
held offline and does not belong on the platform container either.

Copy them from wherever the CA lives (a Qubes vault in this lab, so `qvm-copy`
rather than `scp`), then:

```bash
# On Dom0.
install -d -m 700 /etc/sandboxd/tls
install -m 644 ca.crt        /etc/sandboxd/tls/ca.crt
install -m 644 dom0-lab.crt  /etc/sandboxd/tls/dom0-lab.crt
install -m 600 dom0-lab.key  /etc/sandboxd/tls/dom0-lab.key
ls -l /etc/sandboxd/tls
```

Prove the pair works **before** starting the daemon, so a certificate problem
is not diagnosed as a `sandboxd` bug:

```bash
curl --cacert /etc/sandboxd/tls/ca.crt \
     --cert  /etc/sandboxd/tls/dom0-lab.crt \
     --key   /etc/sandboxd/tls/dom0-lab.key \
     https://192.168.1.10:8443/healthz
# {"status":"ok"}
```

> If this returns an unexplained EOF rather than an error, that is the httpx
> trap `client_tls.py` documents in reverse: under TLS 1.3 the server completes
> the handshake **before** validating the client certificate, so a rejected
> certificate looks like the connection simply ending.

```text
root@drakvuf:~# curl --cacert /etc/sandboxd/tls/ca.crt \
     --cert  /etc/sandboxd/tls/dom0-lab.crt \
     --key   /etc/sandboxd/tls/dom0-lab.key \
     https://192.168.1.10:8443/healthz
# {"status":"ok"}
{"status":"ok"}root@drakvuf:~# 
```

### C3c. The worker token

Generated once at `deploy-platform-lxc.md:1049` with `openssl rand -hex 32`,
and stored in `/etc/sandbox-platform/api.env` on the container. That file is
`0600` and owned by `platform` because it holds every credential in the system.

Read it from there rather than generating a new one — **both sides must have
the same value**, and a fresh token would simply not match:

```bash
# On the Proxmox host. Prints the token; treat the terminal as sensitive.
pct exec 102 -- grep '^WORKER_TOKEN=' /etc/sandbox-platform/api.env
```

On Dom0, put it in a file rather than the shell history:

```bash
install -d -m 700 /etc/sandboxd
umask 077
printf 'WORKER_TOKEN=%s\n' 'REDACTED' > /etc/sandboxd/sandboxd.env
cat >> /etc/sandboxd/sandboxd.env <<'EOF'
SANDBOXD_API=https://192.168.1.10:8443
SANDBOXD_CACERT=/etc/sandboxd/tls/ca.crt
SANDBOXD_CLIENT_CERT=/etc/sandboxd/tls/dom0-lab.crt
SANDBOXD_CLIENT_KEY=/etc/sandboxd/tls/dom0-lab.key
SANDBOXD_MAX_CLONES=2
# The console dials the BROWSER listener, not the worker one. The platform runs
# two uvicorn processes over the same app and the relay pairs sockets in an
# in-process registry, so both ends of a session must reach the SAME one (F11).
SANDBOXD_CONSOLE_API=https://192.168.1.10:8000
SANDBOXD_TOTAL_MIB=10000
EOF
chmod 600 /etc/sandboxd/sandboxd.env
total_memory           : 20479
free_memory            : 10017
sharing_freed_memory   : 0
sharing_used_memory    : 0
xen_commandline        : placeholder dom0_mem=8192M,max:8192M dom0_max_vcpus=8 dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 hpet=legacy-replacement smt=0 sched=credit
```

`SANDBOXD_TOTAL_MIB` has **no default and the daemon refuses to start without
it**. Guessing how much memory Dom0 may give clones is how a host
overcommits, and the symptom is a clone that fails to restore rather than a
number anyone reads. Measure it:

```bash
free -m                       # total, and what Dom0 itself is using
xl info | grep -E 'total_memory|free_memory'
```

Take Xen's `free_memory` and leave headroom. Two clones at 2198 MiB each need
4396; a host reporting 12 GiB free can say `8192` and still have room.

### C3d. Provision the analysis network — **nothing else does it**

> **F4 — this step was missing, and the runbook was wrong without it.**
> `run_analysis-<os>.sh:106,121` brings the bridge up and runs
> `network-setup.sh` before launching `dirwatch`. `sandboxd` replaces the
> launcher but **not** that call — #41 scoped it out on the reasoning that
> "the launcher still does it", which stops being true the moment you run
> `sandboxd` instead of the launcher.
>
> Nothing in `sandboxd` creates `xenbr1.<n>`, the `172.16.<n>.1` gateways or
> the isolation chains. A clone handed a VLAN with no gateway boots, gets an
> address nothing routes, and **reads as a sample that chose not to talk** —
> a false negative wearing the clothes of a result.
>
> If the previous `dirwatch` era left the interfaces in place this appears to
> work, which is exactly how it would go unnoticed.

```bash
# On Dom0. The OVS bridge itself is a one-time install step and is NOT created
# here -- network-setup.sh checks for it and fails naming that step.
ovs-vsctl list-br | grep -x xenbr1 || echo "MISSING: ovs-vsctl add-br xenbr1"

cd /root/drakvuf-multios-sandbox/automation
ip link set xenbr1 up
./network-setup.sh 2                # MUST equal SANDBOXD_MAX_CLONES
echo "exit=$?"
```

The argument and `SANDBOXD_MAX_CLONES` size the same thing from two sides — the
VLAN pool and the sub-interfaces. `network-setup.sh` has `set -eu` and an EXIT
trap since DRAFT-028, so a rejected rule aborts rather than half-provisioning a
network that looks like it works.

Confirm what it made:

```bash
ip -4 addr show | grep -E "xenbr1\.[0-9]+" -A 2
iptables -L DRAKVUF_ISOLATION -n --line-numbers | head
iptables -t nat -L DRAKVUF_NAT -n
```

Expect one `xenbr1.<n>` per clone with `172.16.<n>.1/24`, and all three chains
populated.

```text
root@drakvuf:~/drakvuf-multios-sandbox# ovs-vsctl list-br | grep -x xenbr1 || echo "MISSING: ovs-vsctl add-br xenbr1"

cd /root/drakvuf-multios-sandbox/automation
ip link set xenbr1 up
./network-setup.sh 2                # MUST equal SANDBOXD_MAX_CLONES
echo "exit=$?"
xenbr1
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
exit=0
root@drakvuf:~/drakvuf-multios-sandbox/automation# ip -4 addr show | grep -E "xenbr1\.[0-9]+" -A 2
iptables -L DRAKVUF_ISOLATION -n --line-numbers | head
iptables -t nat -L DRAKVUF_NAT -n
12: xenbr1.1@xenbr1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    inet 172.16.1.1/24 scope global xenbr1.1
       valid_lft forever preferred_lft forever
13: xenbr1.2@xenbr1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    inet 172.16.2.1/24 scope global xenbr1.2
       valid_lft forever preferred_lft forever
Chain DRAKVUF_ISOLATION (1 references)
num  target     prot opt source               destination         
1    DROP       all  --  0.0.0.0/0            0.0.0.0/0           
2    DROP       all  --  0.0.0.0/0            10.0.0.0/8          
3    DROP       all  --  0.0.0.0/0            172.16.0.0/12       
4    DROP       all  --  0.0.0.0/0            192.168.0.0/16      
5    DROP       all  --  0.0.0.0/0            169.254.0.0/16      
6    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0           
7    ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
8    DROP       all  --  0.0.0.0/0            0.0.0.0/0           
Chain DRAKVUF_NAT (1 references)
target     prot opt source               destination         
MASQUERADE  all  --  0.0.0.0/0            0.0.0.0/0   
```

### C3e. Start it

```bash
cd /root/drakvuf-multios-sandbox
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon
```

Expect, in order: a sweep summary, a registration, a reconcile, then idle
claims. **The sweep runs before registration** so stale clones are not counted
as capacity.

```text
root@drakvuf:~/drakvuf-multios-sandbox# set -a; . /etc/sandboxd/sandboxd.env; set +a
root@drakvuf:~/drakvuf-multios-sandbox# .venv-sandboxd/bin/python -m sandboxd.daemon
2026-08-26 21:57:31,593 INFO    sandboxd: sweep: 1 domain(s), 3 LV(s), 0 process(es), 0 config(s); 3 vlan(s) clean, 0 withheld
2026-08-26 21:57:31,603 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/register "HTTP/1.1 204 No Content"
2026-08-26 21:57:31,605 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/reconcile "HTTP/1.1 200 OK"
2026-08-26 21:57:31,690 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/claim "HTTP/1.1 200 OK"
2026-08-26 21:57:31,695 INFO    httpx: HTTP Request: GET https://192.168.1.10:9000/analysis/samples/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/%3CIMG%20onmouseover%3D%22alert%28xxs%29%22%3E?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T195731Z&X-Amz-Expires=120&X-Amz-SignedHeaders=host&X-Amz-Signature=cdbe72efb3cfcd06e936a526c80f4b625c3412ad11b281da573764c3f24e2295 "HTTP/1.1 200 OK"
2026-08-26 21:57:33,284 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/state "HTTP/1.1 204 No Content"
2026-08-26 21:57:38,932 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/state "HTTP/1.1 204 No Content"
2026-08-26 21:57:41,705 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/heartbeat "HTTP/1.1 200 OK"
2026-08-26 21:57:44,966 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/state "HTTP/1.1 204 No Content"
2026-08-26 21:57:44,972 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/artifacts "HTTP/1.1 200 OK"
2026-08-26 21:57:44,983 INFO    httpx: HTTP Request: POST https://192.168.1.10:9000/analysis "HTTP/1.1 204 No Content"
2026-08-26 21:57:44,991 INFO    httpx: HTTP Request: POST https://192.168.1.10:9000/analysis "HTTP/1.1 204 No Content"
2026-08-26 21:57:44,998 INFO    httpx: HTTP Request: POST https://192.168.1.10:9000/analysis "HTTP/1.1 204 No Content"
2026-08-26 21:57:45,006 INFO    httpx: HTTP Request: POST https://192.168.1.10:9000/analysis "HTTP/1.1 204 No Content"
2026-08-26 21:57:47,253 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/state "HTTP/1.1 204 No Content"
2026-08-26 21:57:47,256 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/state "HTTP/1.1 204 No Content"
2026-08-26 21:57:47,258 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/complete "HTTP/1.1 409 Conflict"
2026-08-26 21:57:47,258 ERROR   sandboxd: job 6c8a1bd2-db7a-4763-a7e0-1847c519ee33 ended in an unhandled error
Traceback (most recent call last):
  File "/root/drakvuf-multios-sandbox/sandboxd/daemon.py", line 335, in _work
    outcome = Analysis(self._api, self._runner, self._cfg).run(
  File "/root/drakvuf-multios-sandbox/sandboxd/stages.py", line 248, in run
    self._report_terminal(lease, outcome)
  File "/root/drakvuf-multios-sandbox/sandboxd/stages.py", line 484, in _report_terminal
    self._api.complete(lease.job_id, outcome.manifest)
  File "/root/drakvuf-multios-sandbox/sandboxd/api.py", line 271, in complete
    self._post(f"/api/v1/worker/jobs/{job_id}/complete",
  File "/root/drakvuf-multios-sandbox/sandboxd/api.py", line 337, in _post
    raise ProtocolError(
sandboxd.api.ProtocolError: /api/v1/worker/jobs/6c8a1bd2-db7a-4763-a7e0-1847c519ee33/complete refused with 409: {"detail":"job is completed; the worker no longer owns it"}
2026-08-26 21:57:51,713 INFO    httpx: HTTP Request: POST https://192.168.1.10:8443/api/v1/worker/claim "HTTP/1.1 200 OK"


```

Confirm on the platform that it registered what Dom0 derived:

```bash
pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -c \
  "SELECT * FROM workers; SELECT * FROM worker_pipelines;"
```

`required_mib` should be **2198** for both Ubuntu and Android — `memory = 2048`
from the template `.cfg` plus the 150 MiB overhead. If it is anything else, the
number the daemon computed and the number `platform.md:216` documents have
diverged.

```text
root@pve1:~# pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -c \
  "SELECT * FROM workers; SELECT * FROM worker_pipelines;"
  worker_id  |         registered_at         |         last_seen_at          | total_mib | total_vlans | total_slots 
-------------+-------------------------------+-------------------------------+-----------+-------------+-------------
 fake-worker | 2026-08-23 13:19:52.94548+00  | 2026-08-26 06:15:36.779601+00 |     12082 |           8 |           2
 drakvuf     | 2026-08-26 19:57:31.595769+00 | 2026-08-26 19:57:31.595769+00 |     10000 |           2 |           2
(2 rows)

  worker_id  |   os    | required_mib 
-------------+---------+--------------
 fake-worker | ubuntu  |         2198
 fake-worker | android |         2198
 fake-worker | windows |         6294
 drakvuf     | android |         2198
 drakvuf     | ubuntu  |         2198
(5 rows)

```

## C4. Submit through the UI

Use a **harmless** sample. Not real malware for a first end-to-end run: the
point is to prove the pipeline moves, and a benign ELF fails in the same places
a hostile one would.

```bash
# On any machine, make something trivially traceable.
printf '#!/bin/sh\nid; ls /; sleep 3\n' > /tmp/hello.sh
```

Submit it at `https://sandbox.evilbootloader.com/ui/submit`, target **ubuntu**.

The browser should land on the job page automatically after admission.

Watch for, without reloading:

- [x] The state pill moves `queued → cloning → preparing → executing →
      collecting → cleaning → completed` **on its own** (this is the SSE feed)
- [x] The "Waiting for an analysis host" note disappears when it starts
- [x] The Artifacts tab stops being dimmed when the manifest lands

```text
EVIDENCE C4 — the job id, and the states you saw appear without reloading

I think all states where shown, I don't remind which appeared. The job id is: 7e5251a7-406b-412f-8fbe-8f0c9bbd0825
```

## C5. What Dom0 did

```bash
# While it is running, in another shell:
xl list
lvs | grep clone
ip -4 addr show xenbr1.1
ls -la /var/lib/sandboxd/results/<job-id>/
```

```text
root@drakvuf:/home/user# xl list
lvs | grep clone
ip -4 addr show xenbr1.1
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     8     r-----     339.1
12: xenbr1.1@xenbr1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    inet 172.16.1.1/24 scope global xenbr1.1
       valid_lft forever preferred_lft forever
root@drakvuf:/home/user# ls -la /var/lib/sandboxd/results/
6c8a1bd2-db7a-4763-a7e0-1847c519ee33/ 7e5251a7-406b-412f-8fbe-8f0c9bbd0825/
root@drakvuf:/home/user# ls -la /var/lib/sandboxd/results/
6c8a1bd2-db7a-4763-a7e0-1847c519ee33/ 7e5251a7-406b-412f-8fbe-8f0c9bbd0825/
root@drakvuf:/home/user# ls -la /var/lib/sandboxd/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/
total 26040
drwx------ 3 root    root        4096 ago 26 22:10 .
drwx------ 4 root    root        4096 ago 26 22:10 ..
-rw------- 1 tcpdump tcpdump    27375 ago 26 22:12 capture.pcap
drwx------ 2 root    root        4096 ago 26 22:12 dump
-rw------- 1 root    root         291 ago 26 22:10 preconfig.log
-rw------- 1 root    root          91 ago 26 22:10 preconfig.stderr
-rw------- 1 root    root    26604306 ago 26 22:12 trace.log
-rw------- 1 root    root         683 ago 26 22:10 trace.stderr
```

## C6. What the platform recorded

```bash
pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -x -c \
  "SELECT state, clone_domain, vlan, cleanup_status, failure_stage, failure_reason FROM jobs ORDER BY created_at DESC LIMIT 1"

curl -s https://sandbox.evilbootloader.com/api/v1/jobs/<job-id> | python3 -m json.tool
```

Check the manifest is the DRAFT-018 shape — `schema_version: 1`, and each
artifact an object with `name`, `size_bytes` and a 64-character `sha256`, not a
bare string.

```text
root@pve1:~# pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -x -c \
  "SELECT state, clone_domain, vlan, cleanup_status, failure_stage, failure_reason FROM jobs ORDER BY created_at DESC LIMIT 1"
-[ RECORD 1 ]--+-----------------------
state          | completed
clone_domain   | ubuntu_sandbox-1-clone
vlan           | 1
cleanup_status | clean
failure_stage  | 
failure_reason | 


vscode ➜ /workspaces/sandbox_project (master) $ curl -s https://sandbox.evilbootloader.com/api/v1/jobs/7e5251a7-406b-412f-8fbe-8f0c9bbd0825 -H "cf-access-token: $TOKEN"  | python3 -m json.tool
{
    "id": "7e5251a7-406b-412f-8fbe-8f0c9bbd0825",
    "created_at": "2026-08-26T20:10:30.802286Z",
    "target_os": "ubuntu",
    "submitted_filename": "hello.sh",
    "state": "completed",
    "sha256": "03bf595337279b298e5646783f8bfe865cc389aeb7f9af3c04b70416e00b7347",
    "size_bytes": 28,
    "owner": "evilbootloader@proton.me",
    "updated_at": "2026-08-26T20:12:49.045207Z",
    "detected_type": "POSIX shell script, ASCII text executable",
    "queue_reason": null,
    "failure_stage": null,
    "failure_reason": null,
    "attempt": 1,
    "cancel_requested": false,
    "manifest": {
        "notes": null,
        "artifacts": [
            {
                "name": "capture.pcap",
                "sha256": "4975f02361ef8f7ab3fc32c2e09b4aee841e479e6cbe7b66f7202bd87dc2c1a7",
                "size_bytes": 27375
            },
            {
                "name": "dump/00000000_unknown_fd_8",
                "sha256": "cef72f3504c2f92c54d9469467920a1160cb3c0f92d49dc50e6f0d26ab0fb287",
                "size_bytes": 960
            },
            {
                "name": "dump/00000001_unknown_fd_3",
                "sha256": "7c3fc21979e4e4b7deb5d7f637ca357811db4c6cff31402bbb977e1626f6164f",
                "size_bytes": 4280
            },
            {
                "name": "dump/00000002_unknown_fd_7",
                "sha256": "bbab0890442dd002cdd0640fe3ea0e3bdda145021394d7aaf8ffe9bda4f6d11c",
                "size_bytes": 9006
            },
            {
                "name": "dump/00000003_unknown_fd_4",
                "sha256": "a0235e653f090e42dd1b1b3f5b3b39a6c36f20d64724d2349cfb61db24d3917b",
                "size_bytes": 92917
            },
            {
                "name": "dump/00000004_unknown_fd_10",
                "sha256": "8b9bd08f5c2b4497ee824a6923042386564814bf79c5983b8ca458b7e3d5265f",
                "size_bytes": 89
            },
            {
                "name": "dump/00000005_unknown_fd_6",
                "sha256": "ebc380a10475a4a1987cff6637600595773ccd94ba5f5eb170417697bc74c89b",
                "size_bytes": 4344
            },
            {
                "name": "dump/00000006_unknown_fd_9",
                "sha256": "13c0806cb19c2a3fb4b69e22760c2cee3e2868507000620a69a7ce2bccae26df",
                "size_bytes": 1328
            },
            {
                "name": "dump/00000007_unknown_fd_5",
                "sha256": "5765f2aef3bb3a83ceb9cb2d81033a36de0a8510c18b0c7022c37e3543070df3",
                "size_bytes": 592
            },
            {
                "name": "dump/00000008__apparmor_.access",
                "sha256": "c01a15eb58c19f259a658567452900dddb6d5af914bec3f2b181258c0e0d89e2",
                "size_bytes": 1196
            },
            {
                "name": "dump/00000009__NetworkManager_devices_2.5NP7T3",
                "sha256": "69940b86bf489ee5f19ff6acb58399b50ae9267c47edd4b7ffbd156576b7ea9c",
                "size_bytes": 214
            },
            {
                "name": "dump/00000010__etc_cups_subscriptions.conf.N",
                "sha256": "949a8881e2c7f9b220087503a370836af4b980e2982ce9cd277eb95de57955a5",
                "size_bytes": 607
            },
            {
                "name": "dump/00000011_unknown_fd_14",
                "sha256": "7b0f2fad20a85cf0019788e98b3bf0246e7c45861e5741368767c361c16c2392",
                "size_bytes": 168
            },
            {
                "name": "dump/00000012__apparmor_.access",
                "sha256": "20f1ce0ddec2f79216189cf64d910946a62b12ca54e25d22d9d42bd6823b710b",
                "size_bytes": 3994
            },
            {
                "name": "dump/00000013_unknown_fd_15",
                "sha256": "863ce43e576d4bf8608ce09b92fa60ef18d2150ac70295c468473f19485c69ab",
                "size_bytes": 120
            },
            {
                "name": "dump/00000014_unknown_fd_16",
                "sha256": "df070c0849900928e1e85833cce32020c89d2303a9e960510c3c3b79746448b7",
                "size_bytes": 72
            },
            {
                "name": "dump/00000015_unknown_fd_17",
                "sha256": "e06f05efa38d3061a75c1efdfc403efaaf9be30844e398071a026d4c96081e31",
                "size_bytes": 56
            },
            {
                "name": "dump/00000016__system.slice_apt-daily.service_cgroup.procs",
                "sha256": "35c13bcea40364137be8645193367a5b6e8232cbe6459b2dccc7e1f12cbba0ae",
                "size_bytes": 10
            },
            {
                "name": "dump/00000017__dconf_user",
                "sha256": "05763092714d1a90655d4c3e5965c8ad568b05c2b303ff9440eaacc848f12c2f",
                "size_bytes": 65793
            },
            {
                "name": "dump/00000018_unknown_fd_23",
                "sha256": "86ac2fe2bddae1d91865be9eda7e2d2c20b99027dde53b706ab5be5902d54818",
                "size_bytes": 52
            },
            {
                "name": "dump/00000019__systemd_journal_streams_.#8:40224sGgYI9",
                "sha256": "712aa759975e5f9dd166e6190da5a45a44a3cad2cd4a405bbb15c6691ebeffe7",
                "size_bytes": 218
            },
            {
                "name": "dump/00000020__system.slice_NetworkManager-dispatcher.service_memory.limit_in_bytes",
                "sha256": "ef3e8c8e23cc13484835043cc4cedbce1f815bb1861acfcc70a57431a32df0ce",
                "size_bytes": 20
            },
            {
                "name": "preconfig.log",
                "sha256": "1209c42676d356cf2c7f55de8460c38e4816014560d6c54fc5868da7048f853e",
                "size_bytes": 291
            },
            {
                "name": "preconfig.stderr",
                "sha256": "4674b9a94ad90530809faa56fee5f44d9c30a4b9ba7c745e5a5659a657ec42cf",
                "size_bytes": 91
            },
            {
                "name": "trace.log",
                "sha256": "f3a9f02b2216f5e7ed2f1e16ee2fdd09684bb5c92c8613bdeb3ae8cb457704fe",
                "size_bytes": 26604306
            },
            {
                "name": "trace.stderr",
                "sha256": "d36d29a89c3be35ac3f765b08b9acf3ad7b9dc44e9230bf745ad5e3e76e486b9",
                "size_bytes": 683
            }
        ],
        "documents": [],
        "truncated": false,
        "schema_version": 1
    },
    "artifacts": {
        "capture.pcap": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/capture.pcap?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=aabef4fec25ecc0474d9596eb60e14b7c32581aff7c9364feb3935dcf0be7e38",
        "dump/00000000_unknown_fd_8": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000000_unknown_fd_8?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=41e31acb542528800de234540e42fe9e68220b6f6d943e063d6aaa07b894849f",
        "dump/00000001_unknown_fd_3": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000001_unknown_fd_3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=12453599d3636658fc2c3915b5094b8e267526bfd9585540d58d9576042aada9",
        "dump/00000002_unknown_fd_7": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000002_unknown_fd_7?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=15ce94d5f9e293577075e492de93f068e59d2d09cd330a0dffd944e8d76e7282",
        "dump/00000003_unknown_fd_4": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000003_unknown_fd_4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=8d21aeb98ec91e9569907233cfcab765c4d70eaba28dd622e5b5b5b8d3daa5c2",
        "dump/00000004_unknown_fd_10": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000004_unknown_fd_10?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=46bb094af8e391b096448c23989dbcfd7c9c87385a5bb8bef7e55531198f88c7",
        "dump/00000005_unknown_fd_6": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000005_unknown_fd_6?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=2e5e42299affe9323940c5d9ec8ac3c6e055c39e369a24519d3b13aad983f05c",
        "dump/00000006_unknown_fd_9": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000006_unknown_fd_9?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=b413cca726d54baf847bda45fe03d636848f737852847c35e49c7bd77576b70b",
        "dump/00000007_unknown_fd_5": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000007_unknown_fd_5?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=68c62b5cb5b3597eae9cedf3d4b794da886fd2a85714bb3515309ab522777973",
        "dump/00000008__apparmor_.access": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000008__apparmor_.access?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=e677caba0818dc0e06567c831ad6eab0b77500fecd5f51c6e7417a409beb08a7",
        "dump/00000009__NetworkManager_devices_2.5NP7T3": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000009__NetworkManager_devices_2.5NP7T3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=eb5b1f194b756234f197e90ef168cb88ae69273c8eb0d00451b59aeb0fcbfea4",
        "dump/00000010__etc_cups_subscriptions.conf.N": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000010__etc_cups_subscriptions.conf.N?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=36c31e1cfea68cc6f076d14ad6433e2de5cb983783682cf8ba6dc60d55e5c92d",
        "dump/00000011_unknown_fd_14": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000011_unknown_fd_14?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=719d69c31fbcaeccaea323fb0069eb68eeac1bfc9b76c7cc7af244711515a6b0",
        "dump/00000012__apparmor_.access": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000012__apparmor_.access?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=c6bd04d508feaecb52cc532665c7f73dc4c2e257dee29f551a8f13a9db827cba",
        "dump/00000013_unknown_fd_15": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000013_unknown_fd_15?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=f65a316c82fbec6d71aa1eb9fe9340de79313fb4a31198c512a73e652442424c",
        "dump/00000014_unknown_fd_16": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000014_unknown_fd_16?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=14c580fd63c3fa08337400a374fb277482414433bf489ec7091974d353cf17d6",
        "dump/00000015_unknown_fd_17": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000015_unknown_fd_17?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=dc03b95744312ba0d8bc54994391dc73f8434e895b3120f1e43060ac67499332",
        "dump/00000016__system.slice_apt-daily.service_cgroup.procs": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000016__system.slice_apt-daily.service_cgroup.procs?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=c64361769d7f00554f239c61e8d819d75c8f99877e098c4e7337a0ac27ca4f2c",
        "dump/00000017__dconf_user": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000017__dconf_user?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=3208bf88af06ac7e5ed933b0d01e201c2e25c51970a42b0039317df754071343",
        "dump/00000018_unknown_fd_23": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000018_unknown_fd_23?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=26f8904e870395615597c6e555c6426af9e5988c00e7aa41c308c10c328a5412",
        "dump/00000019__systemd_journal_streams_.#8:40224sGgYI9": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000019__systemd_journal_streams_.%238%3A40224sGgYI9?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=c3f2581c24bfc37204cde6ab4983c3fe08fefb4f2f3fd0b29edc52525f4e29a9",
        "dump/00000020__system.slice_NetworkManager-dispatcher.service_memory.limit_in_bytes": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/dump/00000020__system.slice_NetworkManager-dispatcher.service_memory.limit_in_bytes?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=1609f847457755d5d69b172c87a38221d3351fc9c192db147f98ac9862883966",
        "preconfig.log": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/preconfig.log?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=c827d006d938db1a8c1d513a7bf1bb74f9a7deb6118102e0bf46cf1e4c9cb1df",
        "preconfig.stderr": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/preconfig.stderr?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=a4e2df61e7e68f27bfb8532796218da85d9c2481dbb82cb24b38d891e078d276",
        "trace.log": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/trace.log?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=3fc6c67c91d6db651981aa68b598b9af1a879a9abcf50290969db8ebc2fbd811",
        "trace.stderr": "https://sandbox.evilbootloader.com/analysis/results/7e5251a7-406b-412f-8fbe-8f0c9bbd0825/trace.stderr?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=sandbox-platform-api%2F20260826%2Feu-central-1%2Fs3%2Faws4_request&X-Amz-Date=20260826T201639Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=3981901045ed99da79cff463c40235f6a88a71770087e314775768431a8dcec4"
    },
    "manifest_error": null,
    "interacted": false,
    "manifest_legacy": false,
    "artifacts_expired": false,
    "reserved_ahead": false
}
```

## C7. The clone is gone

The defect this replaces: `dirwatch` ran cleanup only in the timeout branch, so
a **normal completion left its clone running** — malware with NAT'd egress and
nothing watching it — until the next sample happened to take the same VLAN
slot.

```bash
xl list                  # no *-clone domains
lvs | grep clone         # no clone LVs
ls /var/lib/sandboxd/staging/    # empty: the sample was removed
```

```text
root@drakvuf:/home/user# xl list                  # no *-clone domains
lvs | grep clone         # no clone LVs
ls /var/lib/sandboxd/staging/    # empty: the sample was removed
Name                                        ID   Mem VCPUs	State	Time(s)
Domain-0                                     0  8192     8     r-----     341.9
root@drakvuf:/home/user# 
```

---

# Part D — the live console

> **Both halves are built as of 2026-08-26**, after F5 and F6. What has **never
> run** is the VNC port resolution: `xenstore-read` and `xl list -l` are both
> *Candidate* and unverified against a real clone, so D2 is the first thing to
> exercise them.
>
> A console that never appears is most likely that rather than the relay. Check
> `sandboxd`'s log for `no live console for job …`, which names the reason —
> and never fails the analysis, because the console is an observer of the run
> rather than a participant in its lifecycle.

**Do not start Part D until C7 passes.** A console session on a pipeline that
does not tear its clones down is a session on a domain that may outlive it.

## D1. Enable it

Off by default, deliberately.

```bash
# Both services read this file -- see deploy-platform-lxc.md:1463.
pct exec 102 -- bash -c "echo 'CONSOLE_ENABLED=1' >> /etc/sandbox-platform/api.env"
pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser

# Confirm it took, rather than assuming:
pct exec 102 -- bash -c "grep CONSOLE /etc/sandbox-platform/api.env"
```

Restart `sandboxd` too, so it picks up nothing — it needs no flag, which is
itself worth confirming.

## D2. Open a console on a running job

Submit a sample with a longer sleep so there is time to look:

```bash
printf '#!/bin/sh\nid\nsleep 120\n' > /tmp/slow.sh
```

On the job page, once the state reaches **executing**, the console panel should
appear **above the tab bar** — with no reload, because the SSE refresh
re-renders that region.
  
- [x] The panel appears when the state becomes `executing`
- [x] It is above the tabs, not one of them
- [x] A screen appears within ~10s (one heartbeat interval — Dom0 dials out,
      so this is the latency floor of not listening)
- [x] **Clicking a tab does not kill the session.** This is the bug caught in
      review: the console used to live in the region tab clicks replace

```text

```

## D3. Input reaches the guest, and is recorded

Move the mouse and type in the console.

```bash
pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -Atc \
  "SELECT interacted FROM jobs ORDER BY created_at DESC LIMIT 1"
```

`interacted` must be **true** after input, and the job page must say the run
was driven interactively. That flag is a correctness requirement, not
bookkeeping: an interactive run is not comparable to an automated one, and two
reports that look alike must not describe different experiments.

> **If B1 said `-a` is additive**, expect the pointer to fight you here — that
> is `hidsim` moving the mouse randomly, and it means the console and the
> plugin are contending for the same cursor.

```text
root@pve1:~# pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -Atc   "SELECT interacted FROM jobs ORDER BY created_at DESC LIMIT 1"
f
```

## D4. The session ends with the trace

```bash
# Watch the panel when the job leaves `executing`.
```

- [x] The panel disappears when the state changes
- [x] No `sandboxd` process is left holding a socket: `ss -tnp | grep 59`
- [I can move pointer and click] The job completes normally — the console is an observer, never a
      participant in the analysis's lifecycle

```text
root@drakvuf:~/drakvuf-multios-sandbox# ss -tnp | grep 59
CLOSE-WAIT 25     0      192.168.1.144:45920 192.168.1.10:9000 users:(("python",pid=10739,fd=5))


```

---

# Part E — the properties that must survive

## E1. Dom0 still has no inbound listener — **during a session**

This is the check DRAFT-056 says must still pass, and the reason the relay
direction was reversed. Run it **while a console session is open**.

```bash
pct exec 102 -- bash -lc 'curl -m 5 -sv https://192.168.1.139/ ; echo "exit=$?"'
```

Expect a timeout and `exit=28`, exactly as `deploy-platform-lxc.md` step 5
records. **If this connects, stop and report it** — the whole design rests on
it.

```bash
# And from Dom0, what is actually listening:
ss -ltn
```

Nothing on a non-loopback address that was not there before.

```text
root@pve1:~# pct exec 102 -- bash -lc 'curl -m 5 -sv https://192.168.1.144/ ; echo "exit=$?"'
 
*   Trying 192.168.1.144:443...
* Connection timed out after 5002 milliseconds
* closing connection #0
exit=28

root@drakvuf:~/drakvuf-multios-sandbox# ss -ltn
State     Recv-Q     Send-Q         Local Address:Port         Peer Address:Port    Process    
LISTEN    0          4096           127.0.0.53%lo:53                0.0.0.0:*                  
LISTEN    0          128                127.0.0.1:631               0.0.0.0:*                  
LISTEN    0          128                    [::1]:631                  [::]:*                  
root@drakvuf:~/drakvuf-multios-sandbox# 
```

## E2. The console refuses what it should

```bash
# A job that is not executing
curl -s -o /dev/null -w '%{http_code}\n' \
  https://sandbox.evilbootloader.com/api/v1/jobs/<completed-job-id>/console

# With the flag off
pct exec 102 -- bash -c "sed -i 's/CONSOLE_ENABLED=1/CONSOLE_ENABLED=0/' /etc/sandbox-platform/api.env"
pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser
# ...then try to open a console. It should refuse.
```

```text
vscode ➜ /workspaces/sandbox_project (master) $ curl -s -o /dev/null -w '%{http_code}\n' -H "cf-access-token: $TOKEN" \
  https://sandbox.evilbootloader.com/api/v1/jobs/2764462d-a532-41a2-aea9-9f378e7363c2/console
404

With "sed -i 's/CONSOLE_ENABLED=1/CONSOLE_ENABLED=0/' /etc/sandbox-platform/api.env" console does not open
```

## E3. Two orchestrators still refuse to share the host

```bash
# With sandboxd running, try the old launcher:
/root/drakvuf-multios-sandbox/automation/run_analysis-ubuntu.sh
# And with dirwatch running, try sandboxd. Both must refuse.
```

```text
# sandboxd running, then run_analysis-ubuntu.sh
root@drakvuf:~/drakvuf-multios-sandbox# /root/drakvuf-multios-sandbox/automation/run_analysis-ubuntu.sh
DRAKVUF_NAT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
\u00e7DRAKVUF_INPUT  all opt -- in * out *  0.0.0.0/0  -> 0.0.0.0/0  
DRAKVUF_ISOLATION6  all opt    in * out *  ::/0  -> ::/0  
DRAKVUF_INPUT6  all opt    in * out *  ::/0  -> ::/0  
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
DRAKVUF dirwatch v1.1-git20260511151619+52df0bc8-1 Copyright (C) 2014-2024 Tamas K Lengyel
VLAN pool: 1..2 (leases in /run/drakvuf/vlan), worker slots: 2
Memory admission: DISABLED (DRAKVUF_CLONE_MEMORY_MIB unset) -- clones are limited only by worker slots, and concurrent watchers can overcommit this host

# run_analysis-ubuntu.sh, then sandboxd
root@drakvuf:~/drakvuf-multios-sandbox# .venv-sandboxd/bin/python -m sandboxd.daemon
2026-08-27 00:17:37,747 ERROR   sandboxd: a dirwatch is running (pid 15606). Its clones use VLANs 1..MAX_CLONES and so would these -- they would collide on gateway addresses and isolation rules, and nothing would report it. Stop it first; migration is a cutover, not coexistence.
```

---

# Findings

Number them `F1`, `F2`… as they arise, and record what was expected against
what happened. A runbook whose findings section is empty after a first
execution has usually not been read carefully enough.

### F3 — a completed run recorded no manifest

`sandboxd` reported `completed` through `/state` and *then* called
`/complete`, which answered **409 "job is completed; the worker no longer owns
it"**.

`/complete` requires the job to be `cleaning` and **sets `completed` itself**,
together with the manifest, in one committed row — that single row is what
makes publication atomic. So reporting `completed` first did two things at
once: it made `/complete` unreachable, and since `/complete` is the **only**
writer of `jobs.manifest`, the run finished with its artifacts uploaded to the
store and **no record of them**. The Artifacts tab on that job is empty and
always will be.

The analysis itself was fine — the trace ran, the artifacts uploaded. Only the
publication was lost.

**Fixed** in `stages.py:_report_terminal`: `completed` goes through
`/complete` alone; `failed`, `cancelled` and `interrupted` stay on `/state`.

**Why the tests missed it.** `FakeApi.report_state` accepted any state, so an
illegal sequence passed at the desk while the real API answered 409. The fake
now enforces the server's own table from `routers/worker.py:58` — with
`completed` deliberately absent from it, because it is reachable only through
`/complete`. Reverting the fix now fails 12 tests.

**Affected job:** `6c8a1bd2-db7a-4763-a7e0-1847c519ee33` — completed, no
manifest. Not worth recovering; resubmit if the artifacts are wanted.

### F4 — `network-setup.sh` never ran

See C3d. `run_analysis-<os>.sh` calls it before launching `dirwatch`;
`sandboxd` replaces the launcher but not that call. Added as an explicit step.

If the run above nonetheless produced network traffic, the interfaces were
left over from a previous `dirwatch` era — which is exactly how this would go
unnoticed until a fresh Dom0 boot.

### F5 — the WebSocket route was shadowed by a POST on the same path

From the browser: `405 Method Not Allowed`, `Allow: POST`, on
`wss://.../api/v1/jobs/<id>/console`, with noVNC reporting "Session lost".

`request_console` (POST) and the browser relay (WebSocket) were both mounted at
`/api/v1/jobs/{job_id}/console`. Both routers carry that prefix and
`jobs.router` is included first, so the upgrade request matched the HTTP route
and the WebSocket handler was never reached.

**Fixed** — the POST moved to `/console/request`. Both are wanted: the POST sets
`console_requested` *before* the job is executing, so `sandboxd` already knows
by the time there is something to show.

A collision like this is silent at import — nothing warns, the app starts
cleanly, and it appears only as a 405 on an upgrade, which reads like a proxy
problem. There is now a test asserting no path is served by both an HTTP and a
WebSocket route.

### F6 — uvicorn cannot serve WebSockets without a protocol library

Then `404 Not Found` from `server: uvicorn`, **with the route registered**:

```text
['/api/v1/jobs/{job_id}/console', '/api/v1/worker/jobs/{job_id}/console']
...
HTTP/1.1 404 Not Found
server: uvicorn
```

`requirements.txt` pinned `uvicorn==0.52.4` and nothing else. uvicorn does not
implement the WebSocket protocol itself: with neither `websockets` nor
`wsproto` installed it does not handle the upgrade at all, treats the request
as a plain HTTP GET, finds no HTTP route at that path, and 404s.

**Fixed** — `websockets` pinned. (Initially `17.0.1`, corrected to `16.1.1` by
F7 below: Dom0 could not install 17.)

**Why 425 tests did not catch it.** `TestClient` speaks ASGI directly and never
goes through uvicorn's protocol layer, so every WebSocket test passed against a
server that could not serve one — the suite was exercising the app object, not
the deployed shape. There is now an import assertion for a WebSocket protocol
library and a check that it is **pinned**, since installed-as-somebody-else's-
transitive-dependency is how this returns with nothing in the diff to explain
it.

**This one needs `pip install`, not just a pull:**

```bash
pct exec 102 -- su - platform -s /bin/bash -c '
  cd /opt/platform/src && git pull --ff-only
  cd platform && .venv/bin/pip install -r requirements.txt
'
pct exec 102 -- systemctl restart sandbox-api sandbox-api-browser
```

### F7 — `websockets==17.0.1` has no distribution for Dom0's Python

```text
ERROR: Could not find a version that satisfies the requirement
websockets==17.0.1 (from versions: ..., 16.0, 16.1, 16.1.1)
```

The pin came from `pip list` in the **development container**, which runs
Python 3.14. Dom0's is older, and 17 publishes nothing for it — so the version
recorded as "what we use" was one the machine it was for could never install.

**Fixed** — `websockets==16.1.1` on both sides. It carries the same API this
code needs (`websockets.asyncio.client.connect` with `additional_headers`,
added in 14.0), and both suites pass against it.

The general point: a version pinned from whatever the dev container happens to
have is a guess about every other host. Where two machines share a library,
the pin has to be one they can both take.

### F8 — the console could never have started

D2: the panel appeared, the browser's WebSocket reached the relay
(`101 Switching Protocols`, so F5 and F6 are genuinely fixed), and it then sat
at **"Waiting for the analysis host…"** until the pair timeout. `sandboxd`
never dialled out.

The cause was an ordering error written in deliberately, with a comment
claiming it was a limitation:

> *"Checked once, at the start of the trace, rather than watched throughout. A
> session requested mid-trace waits for the next run."*

It is not a limitation, it is an impossibility. A session is scoped to a job
that is **executing**, so the panel only appears once the trace has begun —
which is *after* the check. Every request arrived too late to be seen, on every
run, forever.

**Fixed by removing the request channel entirely.** `sandboxd` now dials as
soon as the trace starts, and the platform holds the socket unpaired until the
browser arrives. There is no latency and nothing to ask for.

The cost is real and is treated in `live-console.md` §4.1b rather than glossed:
a relay socket is now open for **every** analysis on a console-enabled host,
watched or not. `CONSOLE_ENABLED` changes meaning from "consoles may be
requested" to "this host opens a relay socket per analysis" — which is why it
is off by default on both sides.

The worker's side of the pairing also lost its 90s timeout: sized for a
request-driven dial, it would now have the worker give up before the operator
opened the panel. It holds for the trace and closes during teardown instead.

### F9 — the history list did not update

`/ui/jobs` showed `queued` while the analysis had finished: `job.js` loads only
on a job's own page, so the detail view went live and the list it was reached
from stayed frozen.

**Fixed** — the table is polled while any row on the page can still change, and
not at all once they are all terminal.

### F10 — the console socket opened before anyone was watching

`console bridged to 127.0.0.1:5900` appeared at dial time, then the session
died ~40s later saying only `console session ended`.

Two causes. Both pumps sat in `except Exception: pass`, so the code destroyed
the evidence needed to diagnose it. And `open_connection` ran when the
WebSocket was dialled rather than when a viewer arrived — RFB has the SERVER
speak first, so QEMU sent its banner to nobody and gave up.

**Fixed** — errors are raised, and the console socket opens only when the
platform signals a viewer attached (a TEXT frame, where all data is BINARY).

### F11 — the two sides landed in different processes

`console dialled out`, then **never** `console bridged`, and the browser sat
until its timeout. Nothing errored, because both sides were doing exactly what
they should.

The platform runs **two uvicorn processes** over the same app:

| Listener | Who | |
|---|---|---|
| `192.168.1.10:8443` | the worker channel | mutual TLS |
| `192.168.1.10:8000` | the browser, via cloudflared | Access |

The console relay pairs two sockets in an **in-process registry**. `sandboxd`
connected to 8443 and the browser to 8000, so they attached to two different
registries and could never meet. The code comment said "one per process" — an
accurate statement of exactly the wrong property.

**Fixed** — `SANDBOXD_CONSOLE_API` points the console dial at the browser
listener while the rest of the worker channel stays on the mTLS one. Unset, it
falls back and **warns**, because falling back is the case that silently does
not work.

```bash
# Add to /etc/sandboxd/sandboxd.env, then restart sandboxd:
SANDBOXD_CONSOLE_API=https://192.168.1.10:8000
```

### F12 — the worker channel is reachable through the tunnel

Raised while reviewing F11: if `sandboxd` now dials the browser listener, what
else can reach it there?

The ingress for `sandbox.evilbootloader.com` has **no path restriction** — it
routes everything to `192.168.1.10:8000`, `/api/v1/worker/*` included. On that
listener those routes are protected by the worker token at the application
(`worker.router` carries `require_worker_token`, not the Access dependency) and
by Cloudflare Access at the edge.

**This is pre-existing, not caused by F11's fix.** The worker routes have
always been in the app served on 8000. What F11 changed is that they now
matter there: before, `sandboxd` only ever used the LAN-only mTLS listener.

Two layers is not nothing, but the mTLS listener additionally requires a client
certificate and this path does not — so the tunnel route is strictly weaker,
and it depends on the Access application being scoped to every path rather than
to `/ui`.

**Recommended: make those paths never leave the LAN.** First match wins in
cloudflared, so a 404 rule ahead of the catch-all is enough:

```yaml
ingress:
  # The worker channel is LAN-only. sandboxd reaches :8000 directly at
  # 192.168.1.10; nothing on the internet needs these paths, and the mTLS
  # listener is the one that requires a client certificate.
  - hostname: sandbox.evilbootloader.com
    path: ^/api/v1/worker(/|$)
    service: http_status:404

  - hostname: sandbox.evilbootloader.com
    service: https://192.168.1.10:8000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  # ... the objects.evilbootloader.com rules unchanged ...
```

Verify before reloading, and confirm both directions:

```bash
cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
    https://sandbox.evilbootloader.com/api/v1/worker/claim      # -> http_status:404
cloudflared --config /etc/cloudflared/config.yml tunnel ingress rule \
    https://sandbox.evilbootloader.com/api/v1/jobs/x/console    # -> 192.168.1.10:8000
```

The second must still route: the BROWSER's console socket is at
`/api/v1/jobs/{id}/console`, and only the worker half moves off the tunnel.

Then from outside, both must hold:

```bash
curl -si https://sandbox.evilbootloader.com/api/v1/worker/claim | head -1   # 404
# and the UI still works, and a console session still pairs
```

### F13 — a cached stylesheet made a working console display nothing

The console connected, the RFB handshake completed, 68 kB of framebuffer
arrived — and the panel stayed blank.

```js
container: 1176 x 0
canvas:    1024 x 768   →  style: width: 0px; height: 0px
```

noVNC scales its canvas from the **container's measured size**, and the
container had no height because `.console-screen` was in a stylesheet the
browser had cached from before that rule existed.
`getComputedStyle(el).minHeight` read `0px` against a rule saying `320px`,
which is only possible if the rule is not in the CSSOM at all.

**Fixed** — static assets carry `?v=<mtime>`, so a changed file invalidates
the cache and an unchanged one does not.

**Everything below the browser was already correct.** The relay, the pairing,
the deferred socket, the port resolution: all working, and displaying nothing.
Worth remembering as a failure shape — "the feature does not work" pointed at
seven layers of new code, and the answer was a cached file.

```text
F14


```

# After execution

- Commit this file **with the evidence in it**, per the project convention.
- Anything Candidate that Part B settled goes into the living docs:
  `upstream-drakvuf.md` for the `-a` semantics, `live-console.md` §2.2 for the
  VNC port.
- `docs/architecture/live-console.md` §4.6 is closed or updated by B1.
- If Part C passed on Ubuntu, #41's acceptance criteria can start being ticked
  — but Android and the concurrency criterion need their own runs.

---

# F. Host capacity — why two clones crawl

**Reported by the operator 2026-08-26:** with one or two analysis VMs running,
Dom0's CPUs are throttled and the analysis is very laggy.

This section is **diagnosis, not yet evidence.** The mechanism below is
inference from how DRAKVUF works; the numbers that would confirm it have not
been taken. Take them before changing anything.

## F1. The feedback loop this is likely to be

Under DRAKVUF a trapped syscall **pauses the guest vCPU** until Dom0 has run
the plugin callback and single-stepped past the breakpoint. So guest execution
speed is bounded by *Dom0's* event-processing throughput, and the usual
intuition inverts:

> **Giving the clones more CPU makes them slower**, because the CPU comes out
> of Dom0's share, and Dom0 is the bottleneck.

With no pinning, Xen's scheduler sees four guest vCPUs (two clones ×
`vcpus = 2`) plus Dom0's, all runnable, and shares fairly between them. Fair is
exactly wrong here: a guest vCPU spends most of its time blocked on Dom0 and
traps again the moment it resumes, so Dom0 needs a *disproportionate* share and
gets an equal one. Each clone added takes CPU from the thing every clone is
waiting for, which is why the second one hurts far more than linearly.

Two multipliers on top:

- **`syscalls` traps everything.** The help captured in B1 says so directly —
  *"trap all if parameter is absent"* — and no filter file is passed. Every
  `read`, every `epoll_pwait`, every clock call is a VM exit plus a
  single-step.
- **This is nested.** L0 Proxmox/KVM → L1 Xen → L2 guest. Every VM exit costs
  materially more than it would on bare metal, and VM exits are the entire
  workload.

## F2. Measure, before changing anything

The first command may settle it outright.

```sh
xl info | grep -E "nr_cpus|threads_per_core|cores_per_socket|total_memory|free_memory"
cat /proc/cmdline                     # dom0_max_vcpus / dom0_vcpus_pin present?
xl vcpu-list                          # Dom0's vCPUs, and any CPU affinity
```

**If `nr_cpus` is 4 or fewer, stop here** — two clones at `vcpus = 2` already
ask for the whole machine and Dom0 gets what is left over, which is nothing.
That is oversubscription, not a tuning problem, and the fix is either more
vCPUs on the L1 Proxmox VM or fewer concurrent jobs.

Then, *during* a two-clone run:

```sh
xentop -b -i 5 -d 2                   # who is actually burning CPU
```

Read `Domain-0`'s CPU% against the clones'. The prediction is that Dom0 is
pinned at or near its ceiling while the clones sit low — busy waiting on it,
not computing. If instead the clones are high and Dom0 is low, the loop above
is the wrong diagnosis and this section needs rewriting.

EVIDENCE F2 — paste `xl info`, `/proc/cmdline` and one `xentop` sample

```
```

## F3. The fixes, in order of leverage

Not applied. Each needs its own decision, and the first two are Dom0 host
configuration rather than repository changes.

**1. Pin Dom0 to its own pCPUs.** Add to the Xen command line —

    dom0_max_vcpus=2 dom0_vcpus_pin

— and pin the clones to the complement with `cpus = "2-N"` in
`misc/*_sandbox.cfg`. This breaks the feedback loop directly: Dom0 always has
CPU to service traps, so the clones stop waiting on a starved handler. It is
the standard DRAKVUF deployment posture and the change with the most leverage.
Requires a Dom0 reboot.

**2. Cut the trap surface.** Pass a syscall filter file so `syscalls` traps a
chosen set instead of all of them. This is the largest reduction in event rate
available without touching scheduling. **It has a real cost** — a syscall not
on the list is invisible, exactly as `--disable-sysret` costs return values on
Android — so the list belongs in `pipeline-<os>.env` as a reviewable file, not
inline in a script.

**3. One vCPU per clone.** `vcpus = 2` doubles the trap load for a workload
that is usually single-threaded, and adds altp2m view synchronisation across
vCPUs. **Cost: the templates must be re-saved**, because `xl restore` takes the
vCPU count from the saved memory image and not from the `.cfg` — so this is not
a config edit. Worth measuring the win before paying for it.

**4. `-F` and `--disable-sysret` on Ubuntu.** Android already runs both
(`pipeline-android.env:222`) and Ubuntu runs neither. This would very likely
help — but CLAUDE.md says Ubuntu behaviour is not changed unless explicitly
requested, and Ubuntu is the only end-to-end evidenced pipeline in the project.
**Flagged, not done.** It also costs syscall return values, which is why
Android carries `DISABLE_SYSRET` as a switch rather than a constant.

## F4. `sandboxd` does not model CPU at all — DRAFT-061

`ResourceTable` admits a job on **memory, a VLAN and a slot**
(`sandboxd/resources.py:119`). There is no CPU dimension. On a host with RAM to
spare it will therefore happily admit clones until the pCPUs are oversubscribed
and every running analysis slows down together — which is the failure this
section is about, and `sandboxd` cannot currently see it.

`total_slots` is the only thing standing in the way, and it is a number an
operator sets rather than one derived from `xl info`. That is a real gap, not a
tuning preference: **memory is the resource that fails loudly and CPU is the
one that degrades every job at once, silently.** The second is worse, because a
job that merely runs slowly still hits `dirwatch`'s old 180s trace ceiling and
is recorded as a timeout — a capacity problem reported as an analysis result.

Raise as DRAFT-061: derive a vCPU budget from `xl info`, subtract Dom0's pinned
set, and make `acquire()` all-or-nothing across memory, VLAN, slot **and**
vCPUs, the way it already is across the first three.

## F5. Hybrid CPUs — keep Dom0 off the E-cores

**Reported by the operator 2026-08-26:** the host has Intel hybrid cores
(P-cores and E-cores), Dom0 should not be scheduled on the E-cores, and the
Xen VM's Proxmox CPU type is **`host`**.

### F5a. The pinning cannot happen inside Xen

Dom0 is **L1**. Proxmox presents it a set of uniform vCPUs, so Xen cannot tell
which of its `pCPU 0..N-1` is executing on a P-core — and the answer changes as
L0's scheduler migrates the QEMU vCPU threads. `dom0_vcpus_pin` therefore pins
Dom0 to a *virtual* CPU that can be running on an E-core a millisecond later.

**Core-type selection is an L0 (Proxmox) operation.** The Xen-level pinning in
F3 is still worth doing, but it only partitions Dom0 from the clones *within*
whatever L0 hands up — it cannot choose core types. Both levels are needed, in
this order:

    L0 Proxmox : qm affinity              -> Xen VM's threads run only on P-cores
    L1 Xen     : dom0_vcpus_pin + cpus=   -> Dom0 and clones partitioned
                                             within that P-core set

### F5b. `cpu: host` makes this a correctness problem, not only a slow one

`cpu: host` passes the physical CPU's feature set straight through. On a hybrid
part QEMU enumerates CPUID **once**, from whichever core it happened to be on —
and the VM's threads then migrate freely between P-cores and E-cores. The guest
is therefore told about a CPU it is not always executing on.

What still differs on Alder Lake and later:

- **leaf 0x1A** (hybrid core type) — answers differently depending on where it
  is asked;
- **leaf 0xA, the PMU** — P-cores and E-cores expose different counter counts
  and architectural PMU versions;
- **cache topology** — E-cores share L2 in clusters of four, P-cores do not.

The AVX-512 case that used to cause outright `#UD` is mostly gone — Intel fused
it off on P-cores in retail parts for exactly this reason — but the shape
stands. **This is a latent instability worth tracking separately from the
throttling.** If unexplained flakiness appears in Dom0 or in a clone, this is a
candidate cause, and it would not look like a CPU problem.

**Do not "fix" it by changing the CPU model.** Xen needs `vmx` exposed to run
HVM guests at all, and most named QEMU models omit it; `cpu: host` is the usual
way nested virtualisation is enabled on Proxmox and is very likely why it is
set. Changing it is how one discovers DRAKVUF can no longer start a domain.

The convergence is the useful part: **confining the VM to P-cores makes
`cpu: host` honest**, because enumeration and execution then agree. One change
addresses F1's contention *and* removes this hazard.

### F5c. Identify the cores — on the Proxmox host, not Dom0

Do not infer core type from clock speed; the kernel exposes it directly.

```sh
cat /sys/devices/cpu_core/cpus      # P-cores, e.g. 0-15
cat /sys/devices/cpu_atom/cpus      # E-cores, e.g. 16-23
lscpu -e=CPU,CORE,MAXMHZ            # cross-check, and shows SMT siblings
```

On a hybrid Intel part the P-cores are SMT (two threads per core) and the
E-cores are not, so the numbering is not simply "low = fast".

EVIDENCE F5c — paste both `cpus` files and the `lscpu -e` table

```
root@pve1:~# cat /sys/devices/cpu_core/cpus      # P-cores, e.g. 0-15
0-15
root@pve1:~# cat /sys/devices/cpu_atom/cpus      # E-cores, e.g. 16-23
16-31
root@pve1:~# lscpu -e=CPU,CORE,MAXMHZ            # cross-check, and shows SMT siblings
CPU CORE    MAXMHZ
  0    0 5500.0000
  1    0 5500.0000
  2    1 5500.0000
  3    1 5500.0000
  4    2 5800.0000
  5    2 5800.0000
  6    3 5800.0000
  7    3 5800.0000
  8    4 5500.0000
  9    4 5500.0000
 10    5 5500.0000
 11    5 5500.0000
 12    6 5500.0000
 13    6 5500.0000
 14    7 5500.0000
 15    7 5500.0000
 16    8 4300.0000
 17    9 4300.0000
 18   10 4300.0000
 19   11 4300.0000
 20   12 4300.0000
 21   13 4300.0000
 22   14 4300.0000
 23   15 4300.0000
 24   16 4300.0000
 25   17 4300.0000
 26   18 4300.0000
 27   19 4300.0000
 28   20 4300.0000
 29   21 4300.0000
 30   22 4300.0000
 31   23 4300.0000
```

### F5d. Pin the Xen VM to P-cores only

**Candidate — not yet run.** `--affinity` is PVE 7.3+ and takes a CPU list in
the same form as `taskset -c`.

```sh
qm config <vmid> | grep -E "affinity|cores|sockets|cpu:"
qm set <vmid> --affinity 0-15        # the cpu_core list from F5c
qm stop <vmid> && qm start <vmid>    # applied cleanly on a fresh start
```

**Give Dom0 whole cores, not single SMT siblings.** A P-core's two threads
share execution resources, so a Dom0 thread sharing a core with a clone's vCPU
contends for the same pipeline — F1's problem reintroduced one level down,
where Xen cannot see it and cannot schedule around it.

EVIDENCE F5d — `qm config` before and after, and one `xentop` sample after

```
root@pve1:~# qm config 101 | grep -E "affinity|cores|sockets|cpu:"
cores: 20
cpu: host,flags=-hv-evmcs;-hv-tlbflush
sockets: 1
root@pve1:~# qm set 101 --affinity 0-15        # the cpu_core list from F5c
update VM 101: -affinity 0-15
root@pve1:~# qm stop 101 && qm start 101
root@pve1:~# qm config 101 | grep -E "affinity|cores|sockets|cpu:"
affinity: 0-15
cores: 20
cpu: host,flags=-hv-evmcs;-hv-tlbflush
sockets: 1


```

### F5e. What Dom0 sees now

Worth capturing before the change, because it says whether Xen's own load
balancing has been working from a true topology.

```sh
xl info | grep -E "nr_cpus|threads_per_core|cores_per_socket|hw_caps"
grep -m1 -o hybrid /proc/cpuinfo || echo "no hybrid flag visible in Dom0"
```

If the core count or `threads_per_core` does not match a pure P-core set, the
topology Xen schedules against is already fiction.

### Two decisions worth making explicitly

**Disabling E-cores in firmware is a legitimate option.** Blunt, but this is a
dedicated analysis host, and it covers what `qm set --affinity` does not reach.
The cost is the E-cores' throughput for everything else the host does.

**Hybrid cores are a reproducibility hazard independent of speed.** A sample
that times itself — `rdtsc` deltas are ordinary sandbox-detection material —
gets a materially different answer on a P-core than an E-core. DRAKVUF's
single-stepping already distorts guest timing enormously, but that distortion
is at least consistent; core-type roulette adds run-to-run variance to a number
an evasive sample is actively reading. Pinning removes it as a side effect,
which is a second and independent reason to do it.

**SMT and the malware guest — flagged, not resolved.** The standard posture for
a host running untrusted code alongside a privileged domain is `smt=off`:
L1TF/MDS-class leakage is specifically cross-thread, and a clone's vCPU sharing
a physical core with Dom0 is exactly that threat model. It also costs roughly
half the thread count on a host that is already CPU-starved, which conflicts
directly with the rest of section F. That trade-off belongs in a Dom0
threat-model document that does not yet exist, not in a decision made in
passing here.

## F6. The layout that was chosen, and three corrections to F3–F5

Settled with the operator on Dom0 2026-08-27, against real `xl info` and
`xentop` output rather than the estimates F1–F5 were written from. Where this
section disagrees with those, **this one is right** — they are kept unedited
because the reasoning in them is what produced the measurements here.

### F6a. What the host actually is

```
xen_version      : 4.20.1        total_memory : 20479
nr_cpus          : 20            free_memory  : 12082
threads_per_core : 1             xen_scheduler: credit
```

`xl dmesg` reports no rejected parameters — its only hit is
`Unrecognised CPU model 0xb7`, which is Raptor Lake (an i9-13900K: 8 P-cores at
5.5–5.8 GHz on host CPUs 0–15, 16 E-cores on 16–31, per F5c). Xen 4.20 does not
know the model and falls back to a conservative LazyFPU mitigation. Cosmetic.

### F6b. Three corrections

**1. `force-ept=1`, `ept=ad=0` and `sched=credit` are all accepted.** F5 and the
surrounding discussion doubted the first two would parse and claimed credit1 was
removed in Xen 4.19. Both wrong: Xen logs unknown parameters and logged none,
and `xen_scheduler : credit` shows credit1 alive on 4.20. Keep them as
drakvuf.com has them.

**2. `smt=0` is a no-op here, and that is fine.** `threads_per_core : 1` —
Proxmox presents a flat topology, so Xen sees no siblings to disable. It costs
nothing and is kept for parity with the upstream example. It should not be
mistaken for sibling isolation: L1TF/MDS-class leakage is about *physical*
threads, and only L0 decides which physical core a vCPU thread runs on.

**3. F5d's "give Dom0 whole cores" cannot be delivered by `qm set --affinity`.**
That option applies one CPU mask to *all* the VM's threads; it does not pin them
individually, so L0 floats them freely inside the mask. Whole-core allocation
would need per-thread pinning (a hookscript, or `taskset` per QEMU thread). The
only mask-level way to guarantee it is to request no more vCPUs than there are
physical P-cores — which the chosen layout deliberately does not do.

### F6c. The layout

**12 vCPUs**, Proxmox affinity `0-15` (the P-core set from F5c), 20 GB.

```
GRUB_CMDLINE_XEN_DEFAULT="dom0_mem=8192M,max:8192M dom0_max_vcpus=6 \
  dom0_vcpus_pin=1 force-ept=1 ept=ad=0 hap_1gb=0 hap_2mb=0 altp2m=1 \
  hpet=legacy-replacement smt=0 sched=credit"
```

    Dom0    pCPU 0-5        dom0_vcpus_pin
    clones  pCPU 6-11       cpus = "6-11" in misc/*_sandbox.cfg

**`cpus =` is not optional, and it is the half that is easy to miss.**
`dom0_vcpus_pin` pins Dom0 *into* pCPU 0–5; it does not *reserve* them. An
unpinned guest is scheduled wherever Xen likes, including on top of Dom0 — and
because a trapped syscall pauses its vCPU until Dom0 has serviced it, a clone
sharing a pCPU with Dom0 is competing with the thing it is waiting for. That is
F1's loop, surviving a change that looks like it addressed it.

Added to `ubuntu_sandbox.cfg` and `android_sandbox.cfg` 2026-08-27.
`clone.py`'s `rewrite_config` changes only `name`, `vif` and `disk` and passes
everything else through, so it reaches every clone. **No template re-save is
needed for this** — vCPU affinity is a runtime property libxl applies from the
config at restore; only the vCPU *count* comes from the saved memory image.
`windows.cfg` keeps 2 vCPUs and gets its own line when `windows_sandbox.cfg`
exists.

**12 vCPUs exceeds the 8 physical P-cores**, so some vCPUs share a core. That is
the accepted price of the extra parallelism, and it is why F6b(3) matters:
nothing at the Xen level can prevent it.

### F6d. Capacity

```
memory   20479 - 8192 Dom0  ->  12082 free  / 2198 per clone  =  5 clones
cpu      12 - 6 Dom0        ->      6 pCPU  / 1 vCPU per clone =  6 clones
```

**Memory binds first**, which is the good outcome: it is the dimension
`ResourceTable` models, so its admission decisions are correct rather than
optimistic, and DRAFT-061 (F4) drops from "prevents a real failure" to "worth
having for completeness".

    SANDBOXD_TOTAL_MIB=11500

Admits 5 clones (10990) and refuses a 6th (13188), with ~500 MiB of headroom
for fragmentation and Xen's own accounting.

### F6e. The clones already had one working vCPU

`xentop` during a two-template run, 2026-08-27:

```
      NAME  STATE  CPU(sec) CPU(%)    MEM(k) MEM(%)  VCPUS
android_sa ----p-         0    0.0   2081068    9.9      2
VCPUs(sec):   0:         0s
  Domain-0 -----r        61    9.3   8388608   40.0      8
VCPUs(sec):   0:  8s  1:  7s  2:  7s  3:  7s  4:  8s  5:  6s  6:  6s  7:  8s
ubuntu_san ----p-         0    0.0   2081068    9.9      2
VCPUs(sec):   0:         0s
```

`VCPUS` is `max_vcpu_id + 1`, and the per-vCPU breakdown **skips offline
vCPUs** — Domain-0 lists all eight, both templates list only `0:`. So each
template had vCPU 1 *allocated and never brought up by the guest*.

**This corrects the premise of F3(3).** An offline vCPU executes nothing and
traps nothing, so `vcpus = 1` does not reduce the trap rate — it was never
contributing one, and the change will not measurably help the throttling. It is
kept anyway for two narrower reasons: a sample cannot online CPU1 through sysfs
part-way through an analysis and change the shape of its own trace, and DRAKVUF
stops iterating a vCPU that will never run.

It also means the throttling is **not** explained by vCPU count, and the
remaining candidates are the ones F1 named: Dom0/clone contention for the same
pCPUs (addressed by F6c) and `syscalls` trapping every syscall (F3(2), still
open).

EVIDENCE F6 — after applying F6c, one `xentop` sample under two live analyses

```
root@drakvuf:/home/user# xl vcpu-list
Name                        ID  VCPU  CPU State  Time(s) Affinity (Hard / Soft)
Domain-0                     0     0    0   r--     12.8  0 / all
Domain-0                     0     1    1   r--     12.0  1 / all
Domain-0                     0     2    2   -b-     12.5  2 / all
Domain-0                     0     3    3   -b-     14.2  3 / all
Domain-0                     0     4    4   r--     13.3  4 / all
Domain-0                     0     5    5   -b-      8.0  5 / all
ubuntu_sandbox-1-clone       2     0    6   ---      5.2  6-11 / all
ubuntu_sandbox-2-clone       3     0    7   ---      5.0  6-11 / all

root@drakvuf:/home/user# xentop -b -i 5 -d 2
      NAME  STATE  CPU(sec) CPU(%)    MEM(k) MEM(%) VCPUS
  Domain-0 -----r        96  196.7   8388608   40.0     6
ubuntu_san ------         6    6.2   2081092    9.9     1
ubuntu_san -----r         5    7.8   2081092    9.9     1
  Domain-0 -----r       100  198.8   8388608   40.0     6
ubuntu_san ------         6    7.3   2081092    9.9     1
ubuntu_san ------         6    7.6   2081092    9.9     1
  Domain-0 -----r       104  195.9   8388608   40.0     6
ubuntu_san ------         6    7.5   2081092    9.9     1
ubuntu_san ------         6    7.6   2081092    9.9     1
```

**The partition holds.** Dom0 is pinned 1:1 to pCPU 0-5, both clones are
confined to 6-11 and are running on 6 and 7, and the two sets do not overlap.
`VCPUS 1` also confirms `vcpus = 1` took effect and that `xl restore` accepted
a config whose vCPU count differs from the pre-change templates — the mismatch
this runbook warned might block the change did not occur, and no re-save was
needed.

**But the operator reports the analysis is still laggy**, and the numbers say
why. See §F7.

## F7. The bottleneck after pinning: per-event cost, not scheduling

**Dom0 2026-08-27**, from the F6 measurement. Read the two columns together:

    Domain-0   ~197%  of 600% available   ->  ~33% utilised, 4 cores idle
    clone 1      ~7%  of 100%
    clone 2      ~7%  of 100%

**Nothing is CPU-starved.** Dom0 has four idle cores it could hand to a clone
and the clone still cannot use them — so the guest running at ~7% of a single
vCPU is not waiting for a *processor*, it is paused waiting for Dom0 to service
its traps. It spends roughly 93% of wall time stopped.

That closes F1's diagnosis and replaces it. The feedback loop F1 described was
real and the pinning fixed it; what remains is the irreducible cost of trapping
every syscall, which F3(2) named and which no amount of scheduling touches.

Dom0's load also scales predictably from this: ~1 core per active DRAKVUF
instance, so its six cores saturate at roughly six concurrent traces — above
the memory cap of five in F6d. Memory still binds first.

### F7a. `-F` on Ubuntu — applied 2026-08-27

The three levers are not equivalent, and the difference is **information cost**:

| | effect | cost |
|---|---|---|
| `-F` fast singlestep | second altp2m view instead of a full singlestep round trip per hooked event | **none** — same events, same data |
| `--disable-sysret` | roughly halves the events | syscall **return values** |
| syscall filter file | largest reduction available | every syscall not on the list |

Only the first is free, so only the first was applied. `sandboxd/guests.py`
`default_trace_options()` now sets `fast_singlestep=True` for Ubuntu; Android
has run it evidenced since 2026-08-17, and Dom0's Xen 4.20.1 is well past the
4.14 minimum.

This **does** change the evidenced Ubuntu pipeline, which CLAUDE.md forbids
without an explicit request. It was explicitly requested, and the change is one
argument: revert by dropping `fast_singlestep=True`, since the flag is emitted
by `TraceOptions.drakvuf_flags()` and read nowhere else.

`test_ubuntu_traces_without_the_android_flags` was renamed to
`test_ubuntu_keeps_every_syscall_return_value` and now asserts `-F` is present
and `--disable-sysret` is absent. The old name defended "Ubuntu differs from
Android", which was never the property worth protecting; the new one defends
the evidence boundary — Ubuntu may take cheaper delivery of the same trace, and
may not take a cheaper trace.

EVIDENCE F7a — `xentop` with `-F` live: the clone's CPU(%) against the ~7% above

```
root@drakvuf:~# pgrep -a drakvuf
5428 drakvuf -r .../profiles/linux.json -d 6 -i 1415 -m execproc \
      -e /home/carlos/Desktop/slow.sh -F -o json -t 120 \
      -a syscalls -a filetracer -a fileextractor -a memdump -D ... --memdump-dir ...

root@drakvuf:~# xentop -b -i 5 -d 2
      NAME  STATE  CPU(sec) CPU(%)    MEM(k) MEM(%) VCPUS
  Domain-0 -----r       556   99.2   8388608   40.0     6
ubuntu_san ------         4    6.2   2081092    9.9     1
  Domain-0 -----r       558   99.1   8388608   40.0     6
ubuntu_san ------         4    6.0   2081092    9.9     1
  Domain-0 -----r       560   99.6   8388608   40.0     6
ubuntu_san ------         4    6.5   2081092    9.9     1
```

**`-F` produced no measurable gain** — ~6.2% against the ~7% before it. The
comparison is **confounded** and should not be read as a refutation: this run
traced `slow.sh` and the earlier one traced different samples, so the syscall
mixes differ. A clean A/B needs the same sample with and without the flag. It
is kept because it is theoretically sound and costs no information, but this
measurement does not support it.

### F7c. Dom0 at 99% is ONE SATURATED THREAD, not a busy host

This is the finding that supersedes F1, F7 and F7b.

    1 clone   Domain-0  99.2 / 99.1 / 99.6 %   of 600% available
    2 clones  Domain-0 196.7 / 198.8 / 195.9 %

Domain-0 has **six** vCPUs, so its ceiling is 600%. Pinned at 99.x% with a
single trace running, and at almost exactly twice that with two, it is not
"a third utilised" — it is **one DRAKVUF event loop saturating one core**, one
per trace, scaling linearly. Five cores sit idle throughout.

**That is a serialisation bound, and it explains every measurement in §F.** The
guest cannot exceed ~6% because a single-threaded consumer processes every one
of its trapped events and that thread is already flat out. Idle cores cannot be
handed to it. This is why:

- pinning fixed the contention F1 described and changed the guest not at all;
- `-F` did not move it — `-F` makes the *singlestep* cheaper, and the saturated
  thread is spending its time elsewhere (four plugin callbacks and JSON
  serialisation per event);
- adding Dom0 vCPUs would do nothing.

**The only remaining lever is fewer events.** Not faster handling of them.

Concurrency is unaffected and is genuinely good: one core per trace against six
means ~6 concurrent analyses before Dom0 saturates, above the memory cap of
five in F6d. **This lab trades per-trace speed for parallelism, and that is the
right trade for a sandbox** — nobody watches one analysis finish sooner, but
five running at once is five reports.

### F7d. CORRECTION: "is anything being cut off" is not visible in job state

F7b said a rising `timed_out` count would justify paying information cost.
**There is no `timed_out` state.** `JobState` (`platform/sandbox_platform/enums.py:31`)
is `received → … → completed`, plus `rejected`, `cancelled`, `failed` and
`interrupted`.

And `-t 120` is a trace **duration**, not a deadline: DRAKVUF traces for 120
seconds and stops, so a sample cut off mid-behaviour produces a job that
records `completed` exactly like one that finished. Measured 2026-08-27 —
44 completed, 1 failed, 1 rejected, 2 interrupted, and **no state that could
have represented truncation.**

So the question has to be asked of the trace's *contents*, not the job table:
run a sample whose completion is externally observable — one that writes a
known file, or opens a known connection — and check whether that artifact
appears in the results. `slow.sh` is presumably already this. Until a known
sample is demonstrably being truncated, `--disable-sysret` and a syscall filter
stay off: they would stop recording return values for every analysis the lab
ever runs, in exchange for a guest that feels faster to a human watching it.

### F7b. If `-F` is not enough

Next is `--disable-sysret`, then a syscall filter — in that order, because that
is increasing order of what the trace stops recording. **Neither should be
turned on merely because the guest feels slow.** A DRAKVUF trace is slow by
construction, and an analysis that runs at 7% but completes inside `-t 120` and
captures the behaviour has no problem to fix. The question to answer first is
whether samples are being **cut off** by the trace budget, which is visible in
the job state rather than in `xentop`:

```sh
pct exec 102 -- runuser -u platform -- psql -d sandbox_platform -c \
  "SELECT state, count(*) FROM jobs GROUP BY state"
```

A rising `timed_out` count is a real problem and justifies paying information
cost. A slow console with traces that complete is a *console* problem, and
DRAFT-055 is where it belongs — not a reason to stop recording return values
for every analysis the lab ever runs.

---

> ### ANNOTATION 2026-08-27 (code review) — the console env blocks above are now incomplete
>
> **An operator following this runbook verbatim will get no console.** The two
> `sandboxd.env` blocks above (§ the `SANDBOXD_CONSOLE_API` lines) were written
> when `stages.Config.console_enabled` was hard-coded `True`, so setting
> `SANDBOXD_CONSOLE_API` was the only thing a host needed. That default
> contradicted every document describing it — including
> `docs/architecture/live-console.md` § "What bounds it instead" and the
> comment directly above the field — and there was no way to turn it off
> without editing code.
>
> It now defaults to `False` and reads `SANDBOXD_CONSOLE_ENABLED`. Add:
>
> ```sh
> # Off unless this is set. What it enables is a relay socket dialled OUT of
> # the machine that runs malware, once per analysis -- see live-console.md.
> export SANDBOXD_CONSOLE_ENABLED=1
> ```
>
> Anything but `1`/`true`/`yes`/`on` is false, so a typo leaves the console
> off rather than switching it on.
>
> The blocks above are **not edited**: they are what was run on 2026-08-26 and
> the outputs below them belong to that configuration. Two other changes from
> the same review affect what this runbook observes — the worker end of a
> console session now has to hold the job's lease (`X-Worker-Id` is checked
> against `jobs.lease_owner`), and a session whose job has left `executing` is
> ended by `maintenance._loop`. Neither changes a step here for a single-Dom0
> deployment.
