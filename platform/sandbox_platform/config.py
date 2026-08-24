"""Runtime configuration, from the environment.

Issue #36 (DRAFT-043).

Every value is read once at import. There is no config file: the service runs
from a systemd unit in the platform LXC, and an environment block is one
place to look rather than two.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


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

    # --- worker channel ---------------------------------------------------
    # The only credential Dom0 ever holds. Scoped to /api/v1/worker/* and, on
    # job routes, to jobs that worker currently leases.
    worker_token: str = os.environ.get("WORKER_TOKEN", "")

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
    require_access_jwt: bool = os.environ.get("REQUIRE_ACCESS_JWT", "") == "1"

    # e.g. https://yourteam.cloudflareaccess.com -- where the signing keys live.
    access_team_domain: str = os.environ.get("ACCESS_TEAM_DOMAIN", "").rstrip("/")

    # The Access application's AUD tag. Checked on every token: without it a
    # valid JWT for ANY application in the account would be accepted here.
    access_aud: str = os.environ.get("ACCESS_AUD", "")


settings = Settings()
