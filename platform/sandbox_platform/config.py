"""Runtime configuration, from the environment.

Issue #36 (DRAFT-043).

Every value is read once at import. There is no config file: the service runs
from a systemd unit in the platform LXC, and an environment block is one
place to look rather than two.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
import argon2


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _bool(name: str, default: bool) -> bool:
    """Anything but a recognised true value is false.

    Fails closed on a typo, which matters for `console_enabled`: a feature flag
    that turns a capability ON because someone wrote `CONSOLE_ENABLED=ture` is
    worse than one that stays off.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # --- database ---------------------------------------------------------
    # Empty host selects the Unix socket. The API and Postgres share the
    # container, so there is no network hop and therefore no password to
    # store -- peer authentication as the `platform` OS user.
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql:///sandbox_platform"
    )
    pool_min: int = _int("DB_POOL_MIN", 2)
    pool_max: int = _int("DB_POOL_MAX", 10)

    # --- object store -----------------------------------------------------
    #
    # TWO endpoints, and they are not interchangeable.
    #
    # SigV4 signs the Host header, so a presigned URL is valid only against
    # the host it was signed for -- there is no rewriting it afterwards. Dom0
    # reaches MinIO over the LAN; browsers reach it through the Cloudflare
    # tunnel (issue #39). Each audience therefore needs a URL signed for its
    # own hostname, which means two clients over the same bucket.
    #
    # PUBLIC is the API's OWN hostname, not a second one (issue #37). MinIO
    # uses path-style addressing, so every object URL begins `/analysis/`, and
    # cloudflared routes that path to MinIO while everything else goes to the
    # API. One origin, so the browser upload needs no CORS -- and the store
    # inherits the same Cloudflare Access application rather than sitting on a
    # hostname outside it, which is where it was until 2026-08-24.
    #
    # The cost of sharing a namespace: no API or UI route may ever begin
    # `/analysis`, or cloudflared sends it to MinIO and the route silently
    # disappears. Asserted in tests/test_objects.py.
    #
    # INTERNAL is also the only one that makes real network calls -- HEAD and
    # GET during admission. PUBLIC only ever signs, and signing is a local
    # computation, so the API never has to reach the tunnel.
    s3_internal_endpoint: str = os.environ.get(
        "S3_INTERNAL_ENDPOINT", "http://127.0.0.1:9000"
    )
    s3_public_endpoint: str = os.environ.get(
        "S3_PUBLIC_ENDPOINT",
        os.environ.get("S3_INTERNAL_ENDPOINT", "http://127.0.0.1:9000"),
    )
    s3_bucket: str = os.environ.get("S3_BUCKET", "analysis")
    s3_access_key: str = os.environ.get("S3_ACCESS_KEY", "")
    s3_secret_key: str = os.environ.get("S3_SECRET_KEY", "")

    # MUST match MinIO's own configured region (MINIO_SITE_REGION). The region
    # is part of the SigV4 signing scope, so a mismatch fails every presigned
    # URL with a 403 that mentions the signature and never the region -- which
    # is a long afternoon if you do not know to look.
    #
    # For a self-hosted store this is a LABEL, not a routing directive: the
    # data lives wherever the container does. It says Europe because that is
    # where it is, which is what DRAFT-022's GDPR position should rest on
    # rather than on a default nobody chose.
    s3_region: str = os.environ.get("S3_REGION", "eu-central-1")

    # CA bundle for verifying MinIO's certificate on the internal link. Empty
    # means system trust, which is right in development and wrong in
    # deployment -- the LAN certificate is signed by the internal CA (#39).
    s3_ca_bundle: str = os.environ.get("S3_CA_BUNDLE", "")

    # Presigned URL lifetimes, seconds. Short by intent: a presigned URL is a
    # bearer capability, so its TTL is how long a leak stays useful.
    upload_ttl: int = _int("S3_UPLOAD_TTL", 900)        # 15 min
    artifact_get_ttl: int = _int("S3_ARTIFACT_GET_TTL", 300)   # 5 min

    # How long MinIO keeps an object before its lifecycle rule expires it
    # (issue #37). **This does not enforce anything** -- MinIO does the
    # deleting, from the rule `minio/provision.sh` installs. It exists so the
    # API knows the policy, and it MUST match RETENTION_DAYS there.
    #
    # Why the API needs to know: a job row is permanent and its objects are
    # not, so past this window `GET /jobs/{id}` would hand out presigned URLs
    # for objects MinIO has already removed -- a download link that 404s, with
    # nothing to tell a reader whether the artifact was lost or never existed.
    #
    # Age is an approximation of expiry, deliberately erring toward "gone":
    # lifecycle scans run on MinIO's own schedule, so an object may briefly
    # outlive the window. Withholding a link that would have worked is a much
    # smaller cost than offering one that will not.
    #
    # 0 disables it -- objects are kept indefinitely and nothing reclaims the
    # store but the quota refusing writes.
    retention_days: int = _int("RETENTION_DAYS", 30)

    # --- live console (DRAFT-056) -----------------------------------------
    #
    # OFF by default. This is the feature that lets a human drive a running
    # malware VM from a browser, and DRAFT-056 asks for it to be switchable
    # off without a redeploy while confidence is built.
    #
    # With the direction reversed -- Dom0 dials out, see
    # docs/architecture/live-console.md -- it is no longer an exception to
    # "Dom0 never listens", but it is still an interactive channel toward a
    # machine running malware and still the largest deliberate widening of
    # attack surface in the project.
    console_enabled: bool = _bool("CONSOLE_ENABLED", False)

    # A session nobody completes must not hold a slot forever. One heartbeat
    # interval plus margin: sandboxd cannot answer faster than its next beat,
    # which is the latency floor of dialling out rather than listening.
    console_pair_timeout: int = _int("CONSOLE_PAIR_TIMEOUT", 90)

    # **Which origins may open the operator's end of a console.** Empty means
    # same-origin: the handshake's `Origin` must match its own `Host`.
    #
    # The Same-Origin Policy does not apply to WebSockets, so a page on any
    # origin can open one to this endpoint and the browser will attach whatever
    # cookies its SameSite rules permit. `routers/auth.py` defends the JSON
    # routes with a required header, and records that this works because "a
    # cross-site HTML form cannot set a request header" -- a browser WebSocket
    # cannot set one either, so that defence does not reach here and `Origin`,
    # which the browser sets and script cannot forge, is what is left.
    #
    # **What this adds over SameSite, stated precisely rather than overclaimed.**
    # `sandbox_access` is SameSite=Lax, and a WebSocket handshake is not a
    # top-level navigation, so a cross-site dial carries no session cookie of
    # OURS. The exposure is the Access path: `Cf-Access-Jwt-Assertion` is
    # injected by Cloudflare from its own `CF_Authorization` cookie, whose
    # SameSite attribute is Cloudflare's to set and not ours to rely on. So this
    # is defence in depth for the credential we do not control, on the one
    # channel that streams a live malware VM's framebuffer and accepts input
    # back into it.
    #
    # Same-origin by default rather than an allowlist that must be filled in:
    # an unset value has to be SAFE here, because the alternative is a
    # deployment that silently has no check. Set this only where the browser's
    # origin legitimately differs from the Host this app sees.
    console_allowed_origins: tuple[str, ...] = tuple(
        o.strip().rstrip("/")
        for o in os.environ.get("CONSOLE_ALLOWED_ORIGINS", "").split(",")
        if o.strip()
    )

    # --- admission --------------------------------------------------------
    #
    # Refused before a URL is issued, then re-checked against the object's
    # real size -- a client's declared size is a claim, not a fact.
    #
    # At 512 MiB the binding constraint on the browser path is NOT this value:
    # Cloudflare caps request bodies (100 MB on current free plans), and the
    # upload goes through the tunnel. A sample between that cap and this one
    # fails at Cloudflare with their error page rather than here with
    # `rejected_size`, so the message the submitter sees will not mention this
    # setting. Dom0-side submission and LAN uploads are unaffected.
    #
    # Kept at 512 MiB deliberately: lowering it to match the tunnel would also
    # reject samples the lab can already analyse -- CLAUDE.md records
    # `injector` round-tripping 12 MB byte-exact, and APKs go well beyond
    # that.
    max_sample_bytes: int = _int("MAX_SAMPLE_BYTES", 512 * 1024 * 1024)

    # Ceiling on a SINGLE uploaded artifact, bound into the presigned POST
    # policy the same way max_sample_bytes is (issue #37).
    #
    # **This number is not measured.** `sandboxd` has never run, so no real
    # result set from this lab has been sized. 2 GiB is a ceiling well above
    # any single file the pipeline plausibly produces -- a dropped executable
    # or a pcap over a 180s trace -- not a size anything was observed to need.
    #
    # It caps ONE object and does not bound a job, which is a different
    # question: `memdump` dumps the memory regions a process writes, so a run
    # yields many small files rather than one large one, and `max_length` on
    # the request bounds names per call rather than per job -- a worker may
    # call the endpoint repeatedly. `max_job_result_bytes` below is the bound
    # that matters.
    #
    # Neither this nor a presigned PUT can carry an object past S3's 5 GB
    # single-request limit. Anything larger needs multipart upload, which
    # neither form provides.
    max_artifact_bytes: int = _int("MAX_ARTIFACT_BYTES", 2 * 1024 * 1024 * 1024)

    # Total result bytes one attempt may be issued upload tickets for, summed
    # in DECLARED sizes and enforced when a ticket is minted -- before the
    # bytes land, not after.
    #
    # **This exists because the bucket quota is not a prompt guard.** Measured
    # 2026-08-24: 3 MiB was written into a 1 MiB quota with every write
    # accepted, because MinIO enforces quotas against usage statistics its
    # background scanner refreshes rather than at write time. The same bucket
    # refused ~45s later. So the quota stops accumulation over days and permits
    # an overshoot bounded by write rate times scanner interval -- which is not
    # a documented contract and should not be leaned on.
    #
    # Declared sizes are sound accounting here: the presigned POST policy binds
    # each upload to the size it was declared with, so a worker cannot declare
    # one byte and upload a gigabyte.
    #
    # 4 GiB is unmeasured, like max_artifact_bytes -- no real result set from
    # this lab has been sized. Set it from the arithmetic that actually
    # matters: (jobs expected inside the retention window) x (this value)
    # should stay under the bucket quota, or the store fills before retention
    # reclaims anything.
    max_job_result_bytes: int = _int(
        "MAX_JOB_RESULT_BYTES", 4 * 1024 * 1024 * 1024
    )

    # How much of a sample libmagic sees. It needs a header, not a file, and
    # this bounds what an attacker-controlled parse costs in the process that
    # holds every credential on the platform.
    magic_bytes: int = _int("MAGIC_BYTES", 8192)

    # **`WORKER_TOKEN` is gone from the platform** (DRAFT-061). The worker
    # channel used one shared string plus an `X-Worker-Id` header that nothing
    # bound to it, so any token holder could act as any worker -- KNOWN GAP
    # (DRAFT-043/046). Credentials are per worker now, live in
    # `workers.token_hash`, and are issued by `create_worker.py`; the id is
    # looked up FROM the token, so there is no setting for it to be.
    #
    # sandboxd still reads a `WORKER_TOKEN` from its own environment -- that is
    # now ITS credential rather than a secret both ends share.

    # A lease is bookkeeping, not a resource reservation. It expires so a
    # dead worker's jobs stop occupying the queue; it frees nothing on Dom0.
    lease_seconds: int = _int("LEASE_SECONDS", 120)

    # Server-side long-poll budget for /worker/claim. Long-polling rather
    # than a tight loop, because the arrangement this replaces logged one
    # "Holding: need ..." line per second forever with no backoff.
    claim_poll_seconds: float = float(os.environ.get("CLAIM_POLL_SECONDS", 20))
    claim_poll_interval: float = float(os.environ.get("CLAIM_POLL_INTERVAL", 1.0))

    # --- maintenance ------------------------------------------------------
    # How often the sweep in maintenance.py runs. 0 disables it, which is
    # right for tests and wrong everywhere else: with it off, the lease TTL
    # does not expire and abandoned submissions accumulate.
    maintenance_interval: float = float(os.environ.get("MAINTENANCE_INTERVAL", 30))

    # Added to upload_ttl before a `received` job is abandoned. Margin over a
    # measured boundary rather than the boundary itself: a client that starts
    # its upload at second 899 is still mid-request when the policy expires.
    abandon_margin: int = _int("ABANDON_MARGIN_SECONDS", 300)

    # --- browser identity -------------------------------------------------
    #
    # Cloudflare Access authenticates the human and forwards a signed JWT in
    # `Cf-Access-Jwt-Assertion`. Verifying it here is what gives the browser
    # routes an identity at all -- see auth.access_identity.
    #
    # REQUIRE_ACCESS_JWT is set PER LISTENER, in the systemd unit rather than
    # in api.env, because the two listeners have different front doors: the
    # browser one sits behind Access, and the mTLS one is gated by a client
    # certificate at the TLS layer before any handler runs. Enforcing it on
    # both would lock out Dom0 and the command-line tools, which hold
    # certificates and not browser sessions.
    #
    # **`_bool`, not a hand-written `== "1"`.** This was the one boolean here
    # parsed by hand, and it accepted the single spelling `1` -- so
    # `REQUIRE_ACCESS_JWT=true`, which is exactly what works for
    # `CONSOLE_ENABLED` and `REGISTRATION_OPEN`, left this False and Access
    # verification off. That is the direction `_bool`'s docstring argues
    # against, and with a stronger claim on the argument than `console_enabled`
    # has: a false `console_enabled` keeps a capability shut, while a false
    # `require_access_jwt` fails OPEN -- `auth.access_identity` returns None
    # without ever reading the header, so the browser routes lose their
    # identity rather than gain a closed door.
    #
    # `_bool` accepts `"1"`, so a deployment whose unit already sets
    # `REQUIRE_ACCESS_JWT=1` parses identically before and after this change;
    # only the other spellings changed meaning. tests/test_config.py asserts
    # every bool field on this class goes through `_bool`, so the next one
    # cannot be written by hand.
    require_access_jwt: bool = _bool("REQUIRE_ACCESS_JWT", False)

    # e.g. https://yourteam.cloudflareaccess.com -- where the signing keys live.
    access_team_domain: str = os.environ.get("ACCESS_TEAM_DOMAIN", "").rstrip("/")

    # The Access application's AUD tag. Checked on every token: without it a
    # valid JWT for ANY application in the account would be accepted here.
    access_aud: str = os.environ.get("ACCESS_AUD", "")

    # --- credentials this platform issues itself (DRAFT-061) --------------
    #
    # Empty is NOT a usable key: `jwt.encode(payload, "")` succeeds and
    # `jwt.decode(token, "")` verifies it, so an unset value would mean tokens
    # signed with the empty string that verify perfectly against themselves --
    # anyone who guesses it is unset can mint any `sub` they like.
    #
    # Nothing here enforces that, deliberately. The refusal belongs at the use
    # site, the way `authenticated_worker` refuses a credential that names no
    # worker rather than waving it through: this module only reads the
    # environment, and raising at import would take down a process that may
    # never sign anything. It is `credentials._require_signing_key()`, called by
    # BOTH `mint_access_token` and `decode_access_token` -- guarding only the
    # minting side would leave a service that refuses to issue tokens and
    # cheerfully accepts forged ones.
    jwt_signing_key: str = os.environ.get("JWT_SIGNING_KEY", "")

    # **Units in the name, on both sides.** These are two different scales for
    # two different jobs, and the failure mode of getting them confused is
    # silent: an operator setting ACCESS_TOKEN_TTL=3600 meaning seconds would
    # have bought a 60-hour access token, and nothing would have said so.
    # Renamed while nothing consumed them yet, which is the only cheap moment.
    #
    # Short access, long refresh, and that asymmetry is the whole design: the
    # access token is checked by signature alone and CANNOT be withdrawn before
    # it expires, so its lifetime is the window a stolen one stays useful. The
    # refresh token is a database row, so it can be revoked the moment anything
    # looks wrong -- which is what buys the access token the right to be
    # cheap to check.
    access_token_ttl_minutes: int = _int("ACCESS_TOKEN_TTL_MINUTES", 60)
    refresh_token_ttl_days: int = _int("REFRESH_TOKEN_TTL_DAYS", 1)

    # Telegram is the out-of-band channel for both signup verification and
    # password reset (DRAFT-061 decisions 1 and 2), chosen over SMS because it
    # needs no carrier, no per-message cost, and stores a numeric user id
    # instead of a phone number -- a much smaller thing to hold, though still
    # personal data and still in DRAFT-022 scope.
    #
    # **Outbound only, via getUpdates polling, never a webhook.** A webhook is
    # an inbound HTTP endpoint, and this platform has none by design -- no
    # public IP, no open ports, everything through the tunnel. Reaching
    # api.telegram.org from the DomU is unevidenced so far and worth confirming
    # before anything depends on it.
    #
    # Empty must be refused where the call is made, not here. See the note at
    # `jwt_signing_key` above.
    telegram_bot_token: str = os.environ.get("TELEGRAM_BOT_TOKEN", "")

    # **The bound a rate limiter cannot express.** Each argon2id hash holds its
    # full memory cost for as long as it runs, so N requests arriving together
    # allocate N x `argon_params.memory_cost` before any rate-limit window has
    # closed. Limiting attempts per minute does nothing about attempts in the
    # same millisecond; this is what does.
    #
    # 4 x 64 MiB = 256 MiB, against a 4096 MiB DomU (`CURRENT-STATE.md`, applied
    # 2026-09-12) also running Postgres, MinIO, uvicorn and cloudflared. Raise
    # it only alongside the host, and recompute the product -- the number that
    # matters is `memory_cost x this`, never either alone.
    max_concurrent_hashes: int = _int("MAX_CONCURRENT_HASHES", 4)

    # argon2id at RFC 9106's LOW_MEMORY profile: m=64 MiB, t=3, p=4. The HIGH
    # profile is m=2 GiB, which on this host is half the machine for one login.
    #
    # `p=4` matches the DomU's 4 vCPUs as of 2026-09-12; it was asking for four
    # lanes on a two-vCPU host before that reboot.
    #
    # **`default_factory`, because a dataclass refuses an unhashable default**
    # -- `Parameters.__hash__` is None, and assigning the profile directly
    # raised at import, which took the sandboxd suite down with it since its
    # tests import this module.
    #
    # The cost parameters are encoded into each hash string, so raising them
    # later is a rehash-on-next-login rather than a migration. What this shape
    # does NOT give is an environment override: changing m, t or p is a code
    # change and a deploy, which is the one thing this module's header argues
    # against. Worth revisiting the first time someone needs to raise the cost
    # on a running host.
    argon2_params: argon2.Parameters = field(
        default_factory=lambda: argon2.profiles.RFC_9106_LOW_MEMORY
    )

    jwt_issuer: str = os.environ.get("JWT_ISSUER", "")
    jwt_audience: str = os.environ.get("JWT_AUDIENCE", "")

    # **OFF by default**, like `console_enabled` and for the same reason: a
    # flag that opens a capability must not be opened by forgetting to set it.
    # `_bool` fails closed on a typo, which is what makes that true in practice.
    #
    # What it gates is not "an account" but the OPENING GRANT -- `tenants`
    # defaults to an hour of prepaid analysis seconds, so an open registration
    # route is free malware-analysis compute for anyone who can make an email
    # address and a Telegram account. Closed, the only way in is
    # `create_user.py`, run by an operator.
    #
    # Closing it also stops `/start` creating identities, so the row growth that
    # signup permits stops with it rather than continuing silently.
    registration_open: bool = _bool("REGISTRATION_OPEN", False)

    # **Does an unauthenticated caller on this listener mean infrastructure?**
    #
    # OFF by default, and that default is the security property. Until
    # DRAFT-061 this was INFERRED from `REQUIRE_ACCESS_JWT` being unset:
    # `visible_to(None)` returned `TRUE` and scoped nothing, on the reasoning
    # that no Access token could only mean "arrived over the mTLS listener,
    # already gated by a client certificate". That reasoning was sound and it
    # was invisible -- one deployment mistake away from handing every job to
    # anyone, with nothing in the schema or the code saying so.
    #
    # Naming it makes the dangerous state something an operator has to ASK for.
    # Set it on a listener reachable only over the LAN behind a client
    # certificate, and nowhere else. After the cut-over it should be set
    # nowhere at all: the browser listener never wants it, and the worker
    # channel authenticates per worker now rather than by being unauthenticated
    # in a trusted place.
    infrastructure_listener: bool = _bool("INFRASTRUCTURE_LISTENER", False)

    # --- login throttling (DRAFT-061) -------------------------------------
    #
    # Two mechanisms, deliberately. The per-bucket window below is the DoS
    # guard and runs before argon2; per-account lockout is the credential-
    # stuffing guard and runs after the account is identified. Neither
    # substitutes for the other: a window cannot stop a slow distributed
    # attack, and lockout cannot stop a flood against addresses that do not
    # exist.
    attempts_per_window: int = _int("ATTEMPTS_PER_WINDOW", 5)
    window_length_minutes: int = _int("WINDOW_LENGTH_MINUTES", 5)

    lockout_threshold: int = _int("LOCKOUT_THRESHOLD", 5)
    lockout_duration_minutes: int = _int("LOCKOUT_DURATION_MINUTES", 5)

    # How long a failure counts against an account. Without decay a counter
    # only ever rises, and an account locks on its fifth lifetime typo.
    decay_window_minutes: int = _int("DECAY_WINDOW_MINUTES", 5)

    # **Which header carries the real client address, or empty for none.**
    #
    # Empty means use the socket peer, which is correct in development and for
    # any deployment where the app is reachable directly. In THIS deployment
    # the peer is always cloudflared, so every user would share one bucket and
    # the limit would be global rather than per-client.
    #
    # Set it to `CF-Connecting-IP` behind the tunnel, or `X-Forwarded-For`
    # behind Caddy once DRAFT-061's proxy lands. **It is a trust boundary
    # exactly like the verified-subject header**: whatever is named here must
    # be set by the proxy unconditionally on every request, because anything a
    # caller can set themselves turns the limiter into decoration -- rotate the
    # header, reset the bucket.
    #
    # Defaulting to empty is the conservative direction: a misconfiguration
    # makes the limit too coarse, never absent.
    trusted_client_ip_header: str = os.environ.get("TRUSTED_CLIENT_IP_HEADER", "")



settings = Settings()
