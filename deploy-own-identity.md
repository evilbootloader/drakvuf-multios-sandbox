# Deploy DRAFT-061 — our own identity, per-worker credentials, one listener

**Status: NOT YET EXECUTED.** Every command below is **Candidate** until its
`EVIDENCE` block holds real output. Nothing here has run on this Dom0 or on the
platform DomU.

**Issue:** [DRAFT-061](.github/issue-drafts/todo/DRAFT-061.md). Successor to #40
decision 3. F12 shipped separately on 2026-09-10 and is already live.

**What this deploys:** the platform stops relying on Cloudflare Access for
identity and starts issuing its own credentials — passwords, sessions, a second
factor — and the worker channel stops using one shared token.

---

## Why this is not a rolling deploy

Three of the changes below break their counterpart the instant they land, and
they land in one migration:

| Change | Breaks, until its other half is done |
|---|---|
| `workers.token_hash` | **every analysis host.** The shared `WORKER_TOKEN` stops authenticating; each host needs its own, issued by `create_worker.py` |
| `jobs.owner` / `tenants.owner` become `uuid` | the API, until the new code is running — an email cannot be cast to `uuid` |
| `identities` split into `email` / `access_subject` | nothing, but it is what lets Access and passwords coexist during the cut-over |

So: **stop both units, apply, start, then re-credential sandboxd.** Plan for the
platform to be down for the length of steps 4–8, and for analysis to be down
until step 9.

> **DECISION — Caddy and mTLS were dropped from the draft, 2026-09-13.**
> Decisions 4 and 5 wanted mTLS terminated in Caddy so worker routes could
> demand a certificate *and* a JWT. That is not being built: F12 already took
> the worker routes off the tunnel, and per-worker credentials give the channel
> a real identity. The consequence is stated rather than hidden — the worker
> channel is now **one factor on the LAN**, and the draft's property that "a
> compromised platform can mint a worker token but not a worker certificate" is
> gone with it.

---

## 0. Before touching anything

`0009` **rewrites existing rows** in `jobs` and `tenants`. It has no down path.

```bash
# On the platform DomU.
sudo -u postgres pg_dump -Fc sandbox_platform \
  > /var/backups/sandbox_platform-pre-0009-$(date +%F).dump
ls -l /var/backups/sandbox_platform-pre-0009-*.dump
```

```
EVIDENCE 0                                                      2026-09-15
root@platform:~# sudo -u postgres pg_dump -Fc sandbox_platform \
  > /var/backups/sandbox_platform-pre-0009-$(date +%F).dump
ls -l /var/backups/sandbox_platform-pre-0009-*.dump
-rw-r--r-- 1 root root 1078542 Sep 15 10:01 /var/backups/sandbox_platform-pre-0009-2026-09-15.dump

dump size:                              1078542
```

### 0a. The two preconditions 0009 refuses to guess about

Both are `SELECT`s and neither changes anything. **Run them before the
maintenance window**, because the answer to either may be work.

```bash
sudo -u platform psql sandbox_platform -c "
  SELECT DISTINCT owner FROM jobs
  EXCEPT SELECT owner FROM tenants;"

sudo -u platform psql sandbox_platform -c "
  SELECT lower(owner), count(*) FROM tenants GROUP BY 1 HAVING count(*) > 1;"
```

The first must be empty or the migration aborts at `ALTER COLUMN owner TYPE
uuid` — `0008` created `tenants` with no backfill, so a job submitted before it
may have an owner never recorded there. The migration seeds `identities` from
**both** tables to cover that, so an empty result here simply confirms it.

The second must be empty. If it is not, two `tenants` rows differ only in case,
they collapse to one identity, and **the migration aborts by design rather than
silently discarding one prepaid balance.** Sum `balance_seconds` into one row
per address and delete the rest before continuing.

```
EVIDENCE 0a                                                     2026-09-15

owners in jobs but not tenants:         0
case-duplicate owners:                  0
```

### 0b. Confirm the DomU can reach Telegram

Unevidenced so far. Outbound HTTPS works for at least one host — Access
verification fetches Cloudflare's JWKS — but whether egress is allowlisted
per-host is unknown.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://api.telegram.org
```

A `404` is a **success** here: the host resolved and answered. A hang or a
connection error means signup and password reset cannot work, and steps 5 and 9
should set `TELEGRAM_BOT_TOKEN` empty rather than half-configure them.

```
EVIDENCE 0b                                                     2026-09-15
root@platform:~# curl -sS -o /dev/null -w '%{http_code}\n' https://api.telegram.org
302

api.telegram.org:                       302
```

### 0c. Check how `REQUIRE_ACCESS_JWT` is spelled on the live listener

**Candidate.** Until 2026-09-15 this one setting was parsed as
`os.environ.get("REQUIRE_ACCESS_JWT", "") == "1"` while every other boolean went
through `config._bool`, which also accepts `true`, `yes` and `on`. So a listener
configured with the spelling that works everywhere else had Access verification
**silently off** — `access_identity` returned `None` without reading the header.
It fails open, and nothing logs it.

It is set per listener in the systemd unit, not in `api.env`:

```bash
sudo systemctl cat sandbox-api-browser | grep -i REQUIRE_ACCESS_JWT
```

If the value is anything but `1`, Access has not been verifying on that listener
and the jobs behind it were reachable by anyone who got past the tunnel. That is
worth knowing **before** step 10 removes Access, because it changes the question
from "will the cut-over work" to "what was exposed, and for how long". The fix is
already in the code — `_bool` now parses all four spellings — so no action is
needed beyond recording what was there.

```
EVIDENCE 0c                                                     2026-09-15
root@platform:~# sudo systemctl cat sandbox-api-browser | grep -i REQUIRE_ACCESS_JWT
Environment=REQUIRE_ACCESS_JWT=1

REQUIRE_ACCESS_JWT as configured:       yes
```

---

## 1. Pull the code

```bash
cd /opt/platform/src && sudo -u platform git fetch && sudo -u platform git log --oneline -1
sudo -u platform git status --short | head
```

```
EVIDENCE 1                                                      ____-__-__

commit:                                 ______
working tree clean:                     ______
```

## 2. New dependencies

Three, and the third is not a wrapper — Telegram is reached with `httpx`, which
was already present.

```bash
cd /opt/platform/src/platform
sudo -u platform .venv/bin/pip install -r requirements.txt
sudo -u platform .venv/bin/python -c "import argon2, pyotp; print(argon2.__version__, pyotp.__version__)"
```

```
EVIDENCE 2                                                      ____-__-__

argon2-cffi / pyotp:                    ______
```

## 3. The environment block

**Sixteen new settings and one removal.** The removal matters most: the
platform no longer reads `WORKER_TOKEN` at all.

Edit `/etc/sandbox-platform/api.env`.

```ini
# --- credentials this platform issues (DRAFT-061) -----------------------
# NO DEFAULT, and an empty value is not a usable key: an empty HMAC secret
# signs and verifies perfectly, so anyone who guesses it is unset can mint any
# identity. `credentials._require_signing_key` refuses rather than allowing it.
JWT_SIGNING_KEY=<openssl rand -hex 32>
JWT_ISSUER=sandbox.evilbootloader.com
JWT_AUDIENCE=sandbox-platform
ACCESS_TOKEN_TTL_MINUTES=60
REFRESH_TOKEN_TTL_DAYS=1

# --- login throttling ---------------------------------------------------
# Behind cloudflared the socket peer is ALWAYS the tunnel, so without this
# every user shares one rate-limit bucket and the per-IP limit is global.
TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP
ATTEMPTS_PER_WINDOW=5
WINDOW_LENGTH_MINUTES=5
LOCKOUT_THRESHOLD=5
LOCKOUT_DURATION_MINUTES=5
DECAY_WINDOW_MINUTES=5
# 4 x 64 MiB argon2id = 256 MiB peak on a 4096 MiB DomU. Raise only with the
# host, and recompute the PRODUCT -- neither factor alone is the bound.
MAX_CONCURRENT_HASHES=4

# --- self-service signup ------------------------------------------------
# OFF unless you want it. What it gates is not "an account" but the opening
# grant of 3600 analysis seconds, so an open route is free compute for anyone
# with an email address and a Telegram account. Closed, create_user.py is the
# only way in -- and password reset still works for accounts that exist.
REGISTRATION_OPEN=0
TELEGRAM_BOT_TOKEN=<from @BotFather, or leave empty>

# --- live console: which origins may open one ---------------------------
# LEAVE UNSET unless step 12 shows the console failing to pair. Empty means
# same-origin -- the WebSocket handshake's `Origin` must match its own `Host`
# -- and that is the safe default, because an unset value must not mean "no
# check". Set it ONLY if cloudflared presents a `Host` the browser's origin
# does not match; see step 12, which is where that is first observable.
#   CONSOLE_ALLOWED_ORIGINS=https://sandbox.evilbootloader.com

# --- NOT SET, deliberately ----------------------------------------------
# INFRASTRUCTURE_LISTENER makes an UNAUTHENTICATED caller mean "infrastructure"
# and see every job. It exists for the mTLS listener during the transition.
# After step 8 that listener is gone and this must be set nowhere.
```

And **remove** `WORKER_TOKEN` from this file. It is now sandboxd's own
credential, not a secret both ends share.

```bash
sudo grep -c WORKER_TOKEN /etc/sandbox-platform/api.env      # expect: 0
sudo grep -c JWT_SIGNING_KEY /etc/sandbox-platform/api.env   # expect: 1
```

```
EVIDENCE 3                                                      ____-__-__

WORKER_TOKEN removed:                   ______
JWT_SIGNING_KEY present:                ______
```

## 4. Stop both units

```bash
sudo systemctl stop sandbox-api-browser sandbox-api
systemctl is-active sandbox-api-browser sandbox-api          # expect: inactive
```

```
EVIDENCE 4                                                      ____-__-__

is-active:                              ______
```

## 5. Apply migration 0009

```bash
cd /opt/platform/src/platform
sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
  .venv/bin/python migrations/run.py
```

**Once this succeeds, 0009 is immutable.** `run.py` refuses an applied
migration whose bytes have changed, so everything after this point is 0010.

```
EVIDENCE 5                                                      ____-__-__

applied  0009_tenant_credentials.sql:   ______
```

### 5a. Confirm the rewrite, and that objects were left alone

```bash
sudo -u platform psql sandbox_platform -c "
  SELECT data_type FROM information_schema.columns
   WHERE table_name='jobs' AND column_name='owner';"

sudo -u platform psql sandbox_platform -c "
  SELECT count(*) AS rows,
         count(*) FILTER (WHERE key_prefix LIKE 'u/%@%') AS legacy_email_prefix
    FROM jobs;"
```

`jobs.owner` must be `uuid`. **`key_prefix` must still contain email-shaped
prefixes** for pre-existing rows — that is not a missed rewrite, it is the whole
reason this migration is safe against a populated bucket. The objects are where
they are, and every key builder concatenates the stored value.

```
EVIDENCE 5a                                                     ____-__-__

jobs.owner type:                        ______
rows / legacy prefixes:                 ______
```

## 6. Start the API and check it answers

```bash
sudo systemctl start sandbox-api-browser sandbox-api
systemctl is-active sandbox-api-browser sandbox-api
sudo journalctl -u sandbox-api-browser -n 20 --no-pager
```

Expect a `Telegram disabled` warning if `TELEGRAM_BOT_TOKEN` is empty — that is
the intended behaviour, not a fault.

```
EVIDENCE 6                                                      ____-__-__

is-active:                              ______
startup log:                            ______
```

## 7. Credential the analysis hosts

**Do this before expecting any analysis to run.** Repeat per host.

```bash
cd /opt/platform/src/platform
sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
  .venv/bin/python create_worker.py dom0-1
```

The token is printed **once** and only its sha256 is stored. Put it in
`/etc/sandboxd/sandboxd.env` on that host as `WORKER_TOKEN`, then restart
sandboxd — it runs in the foreground and has no unit, so that means stopping and
re-running it per `docs/CURRENT-STATE.md` §1.2.

`--rotate` replaces a credential; the old one stops working immediately, which
is also how a compromised host is cut off.

```
EVIDENCE 7                                                      ____-__-__

create_worker.py dom0-1:                ______
sandboxd restarted and claiming:        ______
```

## 8. Make the first account

With `REGISTRATION_OPEN=0` this is the only way in, and it is how the first
account is made even with signup open — signup needs a Telegram bot.

```bash
cd /opt/platform/src/platform
sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
  .venv/bin/python create_user.py you@example.com --telegram-id <your id>
```

The password is **prompted for, never an argument** — a password in argv is in
`ps` output, shell history and process accounting. Without `--telegram-id`,
password reset will not work for that account.

```
EVIDENCE 8                                                      ____-__-__

created:                                ______
balance:                                ______
```

## 9. Sign in through the tunnel

```bash
# From a browser, not curl: the session cookies are Secure and HttpOnly.
#   https://sandbox.evilbootloader.com/ui/login
```

Then confirm, in order: the login page renders **without** an Access session,
signing in lands on the job list, and the balance appears in the masthead. The
balance is the one that matters — it is the route that proved the session is
accepted by the rest of the API and not only by `/auth/*`.

> **Do not verify this with an anonymous `curl`.** Access is still in front
> until step 10, and it answers a 302 to its own login page regardless of
> whether the platform works. See
> [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#curl-from-outside-returns-the-expected-status-and-proves-nothing).

```
EVIDENCE 9                                                      ____-__-__

/ui/login renders:                      ______
sign-in succeeds:                        ______
balance shown:                          ______
```

### 9a. Enrol the second factor

`/ui/account` → **Set up** → scan or type the key → confirm. **Save the ten
recovery codes**; they are shown once and only their hashes are stored.

Two behaviours to confirm while here, because both were defects fixed on
2026-09-15 and neither is visible from the code path alone:

- **Reloading the page mid-enrolment must NOT invalidate the key you just
  added.** The page used to mint a fresh secret on every load — it POSTed
  `/totp/enrol` to discover whether MFA was on — so a reload silently replaced
  the secret and every code from the authenticator was then wrong, with no
  explanation. It now reads `GET /totp/status`, which returns no secret, and
  only the button mints. Reload deliberately and confirm the code still works.
- **The "Set up" button must actually do something.** It was rendered `hidden`
  with no handler for its whole life.

```
EVIDENCE 9a                                                     ____-__-__

TOTP enrolled:                          ______
recovery codes saved:                   ______
reload mid-enrolment kept the key:      ______
sign-in demands a code:                 ______
```

### 9b. Sign out, and confirm the session is really gone

**Candidate, and worth its own step because the control is new and the
behaviour behind it was broken.** `POST /api/v1/auth/logout` revokes every
refresh token for the account, but no page ever called it — there was no
sign-out control anywhere in the UI. Worse, the refresh cookie is scoped
`Path=/api/v1/auth/refresh`, which is **not** a prefix of `/logout`, so a
browser never sent it there: the route identified nobody, revoked nothing, and
cleared two cookies. The tab looked signed out while every refresh token stayed
live for `REFRESH_TOKEN_TTL_DAYS`. Both are fixed; this is the check.

Sign out from the masthead, then confirm the session is dead rather than merely
forgotten:

```bash
sudo -u platform psql sandbox_platform -c "
  SELECT count(*) FILTER (WHERE revoked_at IS NULL) AS live,
         count(*) AS total
    FROM refresh_tokens r
    JOIN identities i ON i.id = r.owner
   WHERE lower(i.email) = lower('you@example.com');"
```

`live` must be `0`. A non-zero count means the browser did not send the refresh
cookie and the revocation half did not run — which is exactly the bug above, and
means the fix did not reach this deployment.

```
EVIDENCE 9b                                                     ____-__-__

sign-out control present:               ______
live refresh tokens after sign-out:     ______
```

## 10. The cut-over — remove Access

Only after step 9 passes. Until this point both credentials work, which is what
makes a rollback a config change rather than a data decision.

```bash
# 1. REQUIRE_ACCESS_JWT is no longer the gate. Remove it, ACCESS_TEAM_DOMAIN
#    and ACCESS_AUD from api.env.
# 2. In the Cloudflare dashboard, delete the Access APPLICATION for
#    sandbox.evilbootloader.com. KEEP THE TUNNEL -- it is transport, not
#    identity, and it is what means no inbound ports and no public IP.
sudo systemctl restart sandbox-api-browser
```

```bash
# The F12 rule must still hold afterwards. Send a GET: /api/v1/worker/claim is
# POST-only, so 404 means the ingress rule answered and 405 means the request
# reached FastAPI.
curl -si https://sandbox.evilbootloader.com/api/v1/worker/claim | head -1
```

```
EVIDENCE 10                                                     ____-__-__

Access application deleted:             ______
sign-in still works:                    ______
GET /api/v1/worker/claim:               ______
```

## 11. Retire the mTLS listener

`8443` existed to serve the worker channel behind a client certificate. The
worker channel now authenticates per worker, so the second unit has no job —
and it is the **only** thing that would want `INFRASTRUCTURE_LISTENER`.

```bash
sudo systemctl disable --now sandbox-api
systemctl is-enabled sandbox-api                             # expect: disabled
sudo grep -c INFRASTRUCTURE_LISTENER /etc/sandbox-platform/api.env   # expect: 0
```

Confirm `sandboxd` still claims work: it reaches `192.168.1.10:8000` over the
LAN, which is unaffected — but that is a claim worth testing rather than
assuming.

```
EVIDENCE 11                                                     ____-__-__

sandbox-api disabled:                   ______
sandboxd still claiming:                ______
```

## 12. One full analysis

The last acceptance criterion, and the only one that cannot be checked from a
development container.

```bash
# Submit through the UI, watch it reach a terminal state, confirm the balance
# was drawn down, and open a console session while it is executing.
```

> **The console's `Origin` check is UNVERIFIED behind the tunnel, and this step
> is where it is first observable.** Added 2026-09-15: the browser end of the
> console now refuses a handshake whose `Origin` does not match its own `Host`.
> It exists because the Same-Origin Policy does not cover WebSockets and neither
> half of the CSRF defence reaches one — there is no preflight on a handshake,
> and the browser's WebSocket API cannot set a header — so `Origin` is the only
> thing distinguishing the operator's tab from a page on another origin holding
> the same valid session. The far end is an interactive channel into a machine
> running malware.
>
> **What is not known is what `Host` cloudflared presents to uvicorn.** If it
> forwards the original, same-origin matches and the console pairs. If it
> rewrites it, the comparison fails and the panel sits at "Waiting for the
> analysis host…" — which looks exactly like `sandboxd` not dialling out, and is
> the reason this is called out rather than left to be debugged from the
> symptom.
>
> If it fails, set `CONSOLE_ALLOWED_ORIGINS` to the browser's origin in
> `api.env` and restart `sandbox-api-browser`. **Record the `Host` that actually
> arrived either way** — that is the fact this step exists to establish, and it
> decides whether the default stays same-origin or the setting becomes required
> on this deployment.

To tell the two apart, check whether Dom0 dialled at all before blaming the
origin check — `sandboxd` logs `console dialled out for job <id>` when it does:

```bash
# On Dom0, while the job is executing.
journalctl -t sandboxd -n 50 --no-pager | grep -i console || \
  echo "sandboxd runs in the foreground; read its terminal instead"
```

```
EVIDENCE 12                                                     ____-__-__

job reached terminal state:             ______
balance drawn down:                     ______
sandboxd dialled out:                   ______
console session paired:                 ______
Host presented by cloudflared:          ______
CONSOLE_ALLOWED_ORIGINS needed:         ______
```

---

## Rollback

**There is no down path for 0009.** Rolling back means restoring the dump from
step 0 and checking out the previous commit.

```bash
sudo systemctl stop sandbox-api-browser sandbox-api
cd /opt/platform/src && sudo -u platform git checkout <previous sha>
sudo -u postgres dropdb sandbox_platform
sudo -u postgres createdb -E UTF8 -T template0 sandbox_platform
sudo -u postgres pg_restore -d sandbox_platform \
  /var/backups/sandbox_platform-pre-0009-<date>.dump
# Restore WORKER_TOKEN to api.env, and the Access settings.
sudo systemctl start sandbox-api-browser sandbox-api
```

Then re-add the Access application in Cloudflare, and put the **shared**
`WORKER_TOKEN` back on every analysis host.

> **What a rollback loses.** Every account created in the meantime: identities,
> password hashes, TOTP secrets, recovery codes and sessions all live in tables
> `0009` created. Jobs submitted after the deploy go too, and their objects stay
> in MinIO under `u/<uuid>/…` where the restored code cannot address them. That
> asymmetry is the reason to do step 9 promptly rather than a day later — and
> the reason to keep the Access application **configured but unused** for a
> while rather than deleting it at step 10 if there is any doubt.

## Known gaps at deploy time

- **`totp_secret` is stored in the clear.** A database disclosure yields the
  second factor beside the password hash it was meant to be independent of.
  Encryption from `api.env` would not survive a host compromise but would cover
  a dump, a backup or a read-only injection. Decide before MFA is offered
  widely; recorded as `KNOWN GAP (DRAFT-061)` in `0009`.
- **The worker channel is one factor**, per the decision at the top of this
  file. LAN reachability plus a per-worker credential, with no certificate.
- **Login rate limiting has never run without Access in front of it.** The
  mechanism is built and tested; step 10 is the first time it is the only thing
  standing between the internet and argon2.
- **The console's `Origin` check has never run behind cloudflared.** Same-origin
  is the default and the safe direction to fail in — it refuses rather than
  admits — but whether it refuses the legitimate operator depends on a `Host`
  nobody has observed. Step 12 establishes it; `CONSOLE_ALLOWED_ORIGINS` is the
  remedy if it does.
- **`X-Sandbox-Request` is now required on every unsafe method**, not only on
  `/auth/*` — the jobs and account routers demand it too, because two of the
  UI's own calls were CORS-simple requests a cross-site page could have issued.
  Consequence for operators: **a `submit.py` from a checkout older than
  2026-09-15 will get a 403** against the new API. Pull before submitting. GET
  routes are exempt, which is what keeps artifact download links — plain `href`s
  a person clicks — working.
- **A Telegram user id is personal data** and is in DRAFT-022's erasure scope
  exactly like the email. Erasure is: delete refresh and verification tokens,
  drop the credentials row, then null `email` and `telegram_user_id` — the
  foreign keys are `NO ACTION`, so the identity row itself cannot be deleted
  while any job references it, which is deliberate.