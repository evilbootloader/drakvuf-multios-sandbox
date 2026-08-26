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
drakvuf -r <profile> -d <domid> -i <pid> \
    -a syscalls -a filetracer -a fileextractor -a memdump \
    -o json -t 20 2>&1 | grep -i "hid\|plugin" | head -20
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
root@drakvuf:~/drakvuf-multios-sandbox# grep -i "hid\|plugin" /tmp/drakvuf.out | head -20 
{"Plugin":"syscall","TimeStamp":"1787773417.362092","PID":623,"PPID":1,"TID":625,"UserId":111,"ProcessName":"/usr/libexec/rtkit-daemon","Method":"restart_syscall","EventUID":"0x1","ThreadName":"rtkit-daemon","Module":"linux","vCPU":0,"CR3":"0xb6d8000","Syscall":219,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1787773417.363499","PID":910,"PPID":904,"TID":920,"UserId":1000,"ProcessName":"/usr/bin/pulseaudio","Method":"ppoll","EventUID":"0x4","ThreadName":"null-sink","Module":"linux","vCPU":0,"CR3":"0x9e36000","Syscall":271,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1787773417.364301","PID":433,"PPID":1,"TID":459,"UserId":0,"ProcessName":"/usr/lib/accountsservice/accounts-daemon","Method":"restart_syscall","EventUID":"0x7","ThreadName":"gdbus","Module":"linux","vCPU":0,"CR3":"0x40ae000","Syscall":219,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1787773417.364904","PID":433,"PPID":1,"TID":433,"UserId":0,"ProcessName":"/usr/lib/accountsservice/accounts-daemon","Method":"restart_syscall","EventUID":"0xa","ThreadName":"accounts-daemon","Module":"linux","vCPU":0,"CR3":"0x40ae000","Syscall":219,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1787773417.366070","PID":1,"PPID":0,"TID":1,"UserId":0,"ProcessName":"/usr/lib/systemd/systemd","Method":"clock_gettime","EventUID":"0xe","ThreadName":"systemd","Module":"linux","vCPU":0,"CR3":"0x4f02000","Syscall":228,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1787773417.366327","PID":1,"PPID":0,"TID":1,"UserId":0,"ProcessName":"/usr/lib/systemd/systemd","Method":"clock_gettime","EventUID":"0xf","Module":"linux","vCPU":0,"CR3":"0x4f02000","Syscall":228,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1787773417.547480","PID":224,"PPID":1,"TID":224,"UserId":0,"ProcessName":"/usr/lib/systemd/systemd-journald","Method":"clock_gettime","EventUID":"0x10","ThreadName":"systemd-journal","Module":"linux","vCPU":0,"CR3":"0x8f7c000","Syscall":228,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1787773417.547853","PID":224,"PPID":1,"TID":224,"UserId":0,"ProcessName":"/usr/lib/systemd/systemd-journald","Method":"clock_gettime","EventUID":"0x11","Module":"linux","vCPU":0,"CR3":"0x8f7c000","Syscall":228,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1787773417.551461","PID":263,"PPID":1,"TID":263,"UserId":0,"ProcessName":"/usr/lib/systemd/systemd-udevd","Method":"gettid","EventUID":"0x12","ThreadName":"systemd-udevd","Module":"linux","vCPU":0,"CR3":"0x9aac000","Syscall":186,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1787773417.551755","PID":263,"PPID":1,"TID":263,"UserId":0,"ProcessName":"/usr/lib/systemd/systemd-udevd","Method":"gettid","EventUID":"0x13","Module":"linux","vCPU":0,"CR3":"0x9aac000","Syscall":186,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1787773417.555463","PID":408,"PPID":1,"TID":408,"UserId":101,"ProcessName":"/usr/lib/systemd/systemd-resolved","Method":"gettid","EventUID":"0x14","ThreadName":"systemd-resolve","Module":"linux","vCPU":0,"CR3":"0x4dd8000","Syscall":186,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1787773417.555852","PID":408,"PPID":1,"TID":408,"UserId":101,"ProcessName":"/usr/lib/systemd/systemd-resolved","Method":"gettid","EventUID":"0x15","Module":"linux","vCPU":0,"CR3":"0x4dd8000","Syscall":186,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1787773417.559446","PID":409,"PPID":1,"TID":409,"UserId":102,"ProcessName":"/usr/lib/systemd/systemd-timesyncd","Method":"gettid","EventUID":"0x16","ThreadName":"systemd-timesyn","Module":"linux","vCPU":0,"CR3":"0x4dda000","Syscall":186,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1787773417.559776","PID":409,"PPID":1,"TID":409,"UserId":102,"ProcessName":"/usr/lib/systemd/systemd-timesyncd","Method":"gettid","EventUID":"0x17","Module":"linux","vCPU":0,"CR3":"0x4dda000","Syscall":186,"Ret":"0x0","Info":""}
{"Plugin":"syscall","TimeStamp":"1787773417.563200","PID":434,"PPID":1,"TID":434,"UserId":0,"ProcessName":"/usr/sbin/acpid","Method":"select","EventUID":"0x18","ThreadName":"acpid","Module":"linux","vCPU":0,"CR3":"0x40b4000","Syscall":23,"NArgs":5,"Type":"x64","nfds":"0xa","readfds":"0x7ffcd538fb60","writefds":"0x0","exceptfds":"0x7f3c0983319a","timeout":"0x0"}
{"Plugin":"syscall","TimeStamp":"1787773417.564145","PID":435,"PPID":1,"TID":435,"UserId":0,"ProcessName":"/usr/sbin/anacron","Method":"rt_sigsuspend","EventUID":"0x1b","ThreadName":"anacron","Module":"linux","vCPU":0,"CR3":"0x40aa000","Syscall":130,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1787773417.564867","PID":439,"PPID":1,"TID":439,"UserId":115,"ProcessName":"/usr/sbin/avahi-daemon","Method":"restart_syscall","EventUID":"0x1e","ThreadName":"avahi-daemon","Module":"linux","vCPU":0,"CR3":"0x40b8000","Syscall":219,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1787773417.566225","PID":443,"PPID":1,"TID":443,"UserId":0,"ProcessName":"/usr/sbin/cupsd","Method":"epoll_wait","EventUID":"0x22","ThreadName":"cupsd","Module":"linux","vCPU":0,"CR3":"0xad20000","Syscall":232,"NArgs":0,"Type":"x64"}
{"Plugin":"syscall","TimeStamp":"1787773417.567036","PID":444,"PPID":1,"TID":444,"UserId":103,"ProcessName":"/usr/bin/dbus-daemon","Method":"clock_gettime","EventUID":"0x25","ThreadName":"dbus-daemon","Module":"linux","vCPU":0,"CR3":"0x40bc000","Syscall":228,"NArgs":0,"Type":"x64"}
{"Plugin":"sysret","TimeStamp":"1787773417.567381","PID":444,"PPID":1,"TID":444,"UserId":103,"ProcessName":"/usr/bin/dbus-daemon","Method":"clock_gettime","EventUID":"0x26","Module":"linux","vCPU":0,"CR3":"0x40bc000","Syscall":228,"Ret":"0x0","Info":""}
root@drakvuf:~/drakvuf-multios-sandbox# grep -i "hid" /tmp/drakvuf.out | head -20 
{"Plugin":"syscall","TimeStamp":"1787773501.232386","PID":1596,"PPID":1,"TID":1596,"UserId":0,"ProcessName":"/usr/lib/apt/apt-helper","Method":"openat","EventUID":"0xfac7","ThreadName":"apt-helper","Module":"linux","vCPU":0,"CR3":"0x4f00000","Syscall":257,"NArgs":4,"Type":"x64","dirfd":"0xffffff9c","pathname":"/etc/apt/apt.conf.d/60icons-hidpi","flags":"0x80100","mode":"0x21614f5b"}
```

**If additive:** every past trace contains synthetic mouse input, that fact
belongs in `docs/architecture/upstream-drakvuf.md`, and `sandboxd` needs a way
to suppress it before a console session is usable. Find the option in the full
help — there may be no way to disable a default-on plugin except by listing
plugins differently.

**If restrictive:** `hidsim` has never run, nothing to reconcile, and DRAFT-055
starts from zero as its draft assumes.

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
export SANDBOXD_MAX_CLONES=2         # MUST match network-setup.sh's argument
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
.venv-sandboxd/bin/pip install httpx websockets==17.0.1
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
- [ ] It is above the tabs, not one of them
- [ ] A screen appears within ~10s (one heartbeat interval — Dom0 dials out,
      so this is the latency floor of not listening)
- [ ] **Clicking a tab does not kill the session.** This is the bug caught in
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
EVIDENCE D3


```

## D4. The session ends with the trace

```bash
# Watch the panel when the job leaves `executing`.
```

- [ ] The panel disappears when the state changes
- [ ] No `sandboxd` process is left holding a socket: `ss -tnp | grep 59`
- [ ] The job completes normally — the console is an observer, never a
      participant in the analysis's lifecycle

```text
EVIDENCE D4


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
EVIDENCE E1 — run DURING a live console session


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
EVIDENCE E2


```

## E3. Two orchestrators still refuse to share the host

```bash
# With sandboxd running, try the old launcher:
/root/drakvuf-multios-sandbox/automation/run_analysis-ubuntu.sh
# And with dirwatch running, try sandboxd. Both must refuse.
```

```text
EVIDENCE E3


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

```text
F5


```

# After execution

- Commit this file **with the evidence in it**, per the project convention.
- Anything Candidate that Part B settled goes into the living docs:
  `upstream-drakvuf.md` for the `-a` semantics, `live-console.md` §2.2 for the
  VNC port.
- `docs/architecture/live-console.md` §4.6 is closed or updated by B1.
- If Part C passed on Ubuntu, #41's acceptance criteria can start being ticked
  — but Android and the concurrency criterion need their own runs.
