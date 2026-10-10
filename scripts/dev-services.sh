#!/bin/sh
# Bring up the services `platform/tests` needs, in a development container.
#
# **This is not a deployment script.** It exists because `CLAUDE.md` and
# `README.md` both name `cd platform && .venv/bin/python -m pytest -q` as a
# standard command, and in a fresh container that command cannot run: the
# Postgres cluster is installed but down, and no object store is installed at
# all. A documented command that fails is worse than an undocumented one,
# because the failure looks like a defect in the code under test.
#
# **Two object stores, selected by `OBJECT_STORE`.** MinIO is the default
# because MinIO is what the deployment runs today; `OBJECT_STORE=garage` is
# the store the deployment is migrating TO (runbook 18). Both paths exist
# because a suite that only ever meets one of them cannot tell you that the
# code works against either -- and CI runs both for the same reason.
#
#     OBJECT_STORE=garage scripts/dev-services.sh
#
# **Flip the default to garage in the same change that cuts the deployment
# over**, and delete the MinIO half once nothing runs it. Until then the
# summary line names the store that is up, loudly, because a developer who
# does not know which store answered cannot read a failure.
#
# Idempotent by design -- running it when everything is already up changes
# nothing and prints the same summary, which is what makes it safe to put in
# front of the test command.
#
# **It installs nothing from the network.** A missing binary is reported with
# the command that would fetch it; whether to run that is the operator's
# decision, not a side effect of preparing to run tests.
#
# NEVER run this against the deployment. It creates a database whose whole
# purpose is to be truncated by the `conn` fixture.
set -eu

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

TEST_DB="sandbox_platform_test"

# minio | garage. See the header for why minio is the default.
OBJECT_STORE="${OBJECT_STORE:-minio}"

MINIO_DATA="${MINIO_DATA:-/tmp/minio-data}"
MINIO_LOG="${MINIO_LOG:-/tmp/minio.log}"

GARAGE_DIR="${GARAGE_DIR:-/tmp/garage-dev}"
GARAGE_LOG="${GARAGE_LOG:-/tmp/garage.log}"
GARAGE_VERSION="${GARAGE_VERSION:-v2.4.1}"

# These four MUST match `platform/tests/conftest.py`'s defaults. It reads the
# environment once, at import, so a mismatch here is not a warning -- it is a
# test failure attributed to whatever the test was actually about.
#
# The lengths are Garage's minimums -- a key id under 8 characters or a secret
# under 16 is refused by `garage key import` -- and MinIO accepts both, which
# is what lets one pair serve either store. conftest.py says the same thing
# from the other side.
S3_ACCESS_KEY="devrootkey"
S3_SECRET_KEY="devrootpassphrase"
S3_BUCKET="analysis"
S3_REGION="eu-central-1"

pg_ok=0
store_ok=0

say() { printf '%s\n' "$*"; }

# --- Postgres --------------------------------------------------------------

if pg_isready -q 2>/dev/null; then
    say "postgres      already up"
    pg_ok=1
else
    # The cluster version is discovered, not hardcoded: this container has 18
    # and the deployment has 17, and pinning either one here would break the
    # other the first time someone rebuilt the image.
    ver="$(pg_lsclusters -h 2>/dev/null | awk 'NR==1 {print $1}')"
    if [ -z "$ver" ]; then
        say "postgres      NOT INSTALLED -- apt-get install postgresql"
    else
        say "postgres      starting cluster $ver/main"
        sudo pg_ctlcluster "$ver" main start || true
        pg_isready -q 2>/dev/null && pg_ok=1
    fi
fi

if [ "$pg_ok" = 1 ]; then
    # `createuser` and `createdb` both fail loudly when the object exists, and
    # that failure is the normal case on a re-run -- hence `|| true` with a
    # separate existence check for the summary.
    sudo -n runuser -u postgres -- createuser -s "$(id -un)" 2>/dev/null || true
    if ! psql -lqtA 2>/dev/null | cut -d'|' -f1 | grep -qx "$TEST_DB"; then
        say "postgres      creating $TEST_DB"
        sudo -n runuser -u postgres -- createdb -O "$(id -un)" "$TEST_DB"
    fi
    say "postgres      $TEST_DB ready"
fi

# --- the object store ------------------------------------------------------

if [ "$OBJECT_STORE" = minio ]; then

# MINIO_SITE_REGION is the one that bites. The region is part of the SigV4
# signing scope, so a MinIO with no region set rejects every presigned URL the
# API generates -- with a 403 that discusses signatures and never mentions
# regions. Do not probe it with `mc admin config get local region`, which
# reports empty for an env-set value; use `... get local site`.

MINIO_BIN="${MINIO_BIN:-$(command -v minio || true)}"

if curl -fsS -o /dev/null -m 2 "http://127.0.0.1:9000/minio/health/live" 2>/dev/null; then
    say "minio         already up on 127.0.0.1:9000"
    store_ok=1
elif [ -z "$MINIO_BIN" ]; then
    # **dl.min.io is gone -- every path under it answers 410, 2026-09-16.** The
    # hint printed here used to fetch linux-amd64/minio from there. GitHub's
    # release assets still serve the pinned build, and that is now the only
    # source: MinIO deleted `minio/minio` from Docker Hub in the same week, and
    # the release AFTER this one ships no binaries at all. The version is
    # spelled out rather than tracking a moving `latest` because it must match
    # the pin in .github/workflows/static-checks.yml -- a developer whose MinIO
    # differs from CI's gets failures nobody can reproduce.
    #
    # **This is also the whole argument for runbook 18.** The community edition
    # was archived on 2026-04-25 and CVE-2026-97731 is unfixed in it, so this
    # pin can never move again. `OBJECT_STORE=garage` is the way out.
    MINIO_REL="RELEASE.2025-09-07T16-13-09Z"
    say "minio         NOT INSTALLED -- tests needing object storage will fail"
    # One line, however long. A URL wrapped with a backslash rejoins with the
    # next line's indentation still in it, so the paste fetches nothing.
    say "              curl -fsSLo ~/.local/bin/minio \\"
    say "                https://github.com/minio/minio/releases/download/$MINIO_REL/minio.linux-amd64.$MINIO_REL"
    say "              chmod +x ~/.local/bin/minio"
    say "              ...or skip it entirely: OBJECT_STORE=garage $0"
else
    say "minio         starting on 127.0.0.1:9000 (log: $MINIO_LOG)"
    mkdir -p "$MINIO_DATA"
    MINIO_ROOT_USER="$S3_ACCESS_KEY" \
    MINIO_ROOT_PASSWORD="$S3_SECRET_KEY" \
    MINIO_SITE_REGION="$S3_REGION" \
        "$MINIO_BIN" server "$MINIO_DATA" \
            --address 127.0.0.1:9000 \
            --console-address 127.0.0.1:9001 >"$MINIO_LOG" 2>&1 &

    n=0
    while [ "$n" -lt 30 ]; do
        if curl -fsS -o /dev/null -m 1 "http://127.0.0.1:9000/minio/health/live" 2>/dev/null
        then store_ok=1; break; fi
        n=$((n + 1))
        sleep 1
    done
    [ "$store_ok" = 1 ] || say "minio         FAILED to come up -- see $MINIO_LOG"
fi

# The bucket is created here because nothing else does. `conftest.py` writes
# objects into it directly, and the deployment's provisioning script needs an
# admin plane and is written for a deployment, not for tests.
if [ "$store_ok" = 1 ] && [ -x "$REPO_ROOT/platform/.venv/bin/python" ]; then
    S3_ACCESS_KEY="$S3_ACCESS_KEY" S3_SECRET_KEY="$S3_SECRET_KEY" \
    S3_BUCKET="$S3_BUCKET" S3_REGION="$S3_REGION" \
    "$REPO_ROOT/platform/.venv/bin/python" - <<"PY" || true
import os

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

s3 = boto3.client(
    "s3", endpoint_url="http://127.0.0.1:9000",
    aws_access_key_id=os.environ["S3_ACCESS_KEY"],
    aws_secret_access_key=os.environ["S3_SECRET_KEY"],
    region_name=os.environ["S3_REGION"],
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)
bucket = os.environ["S3_BUCKET"]
try:
    s3.head_bucket(Bucket=bucket)
    print(f"minio         bucket {bucket} ready")
except ClientError:
    s3.create_bucket(Bucket=bucket)
    print(f"minio         bucket {bucket} created")
PY
fi

else   # ---------------------------------------------------------- garage ----

# Garage binds 127.0.0.1:9000 here, where the deployment puts nginx in front
# and keeps Garage on 3900. conftest.py's endpoints are fixed defaults and the
# documented command passes no environment, so the store has to answer on the
# port it expects. This container has no front, which is why the capability
# checks live in platform/garage/conformance.py and tests/test_object_front.py
# and skip when no front is configured.

GARAGE_BIN="${GARAGE_BIN:-$(command -v garage || true)}"
if [ -z "$GARAGE_BIN" ] && [ -x "$GARAGE_DIR/garage" ]; then
    GARAGE_BIN="$GARAGE_DIR/garage"
fi

g() { "$GARAGE_BIN" -c "$GARAGE_DIR/garage.toml" "$@"; }

if curl -fsS -o /dev/null -m 2 "http://127.0.0.1:3903/health" 2>/dev/null; then
    say "garage        already up on 127.0.0.1:9000"
    store_ok=1
elif [ -z "$GARAGE_BIN" ]; then
    say "garage        NOT INSTALLED -- tests needing object storage will fail"
    say "              mkdir -p $GARAGE_DIR && curl -fsSLo $GARAGE_DIR/garage \\"
    say "                https://garagehq.deuxfleurs.fr/_releases/$GARAGE_VERSION/x86_64-unknown-linux-musl/garage"
    say "              chmod +x $GARAGE_DIR/garage"
    say "              (nothing publishes a checksum beside it -- runbook 18 FINDING C-1)"
else
    mkdir -p "$GARAGE_DIR/meta" "$GARAGE_DIR/data"
    # Rewritten every run: the rpc_secret is throwaway, and a config left from
    # a different GARAGE_DIR is worse than a fresh one.
    cat > "$GARAGE_DIR/garage.toml" <<EOF
metadata_dir = "$GARAGE_DIR/meta"
data_dir     = "$GARAGE_DIR/data"
db_engine    = "lmdb"
replication_factor = 1
rpc_bind_addr   = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret      = "$(openssl rand -hex 32)"
[s3_api]
s3_region     = "$S3_REGION"
api_bind_addr = "127.0.0.1:9000"
[admin]
api_bind_addr = "127.0.0.1:3903"
EOF
    # Garage refuses to start on a world-readable secret file.
    chmod 600 "$GARAGE_DIR/garage.toml"

    say "garage        starting on 127.0.0.1:9000 (log: $GARAGE_LOG)"
    "$GARAGE_BIN" -c "$GARAGE_DIR/garage.toml" server >"$GARAGE_LOG" 2>&1 &

    # /health answers 503 until a layout exists, so wait for the port to be
    # answering at all rather than for a 200.
    n=0
    while [ "$n" -lt 30 ]; do
        if curl -s -o /dev/null -m 1 "http://127.0.0.1:3903/health" 2>/dev/null; then break; fi
        n=$((n + 1))
        sleep 1
    done

    # A node with no layout accepts no writes and /health stays 503.
    if g status 2>/dev/null | grep -q 'NO ROLE ASSIGNED'; then
        say "garage        assigning a layout"
        node="$(g node id -q 2>/dev/null | cut -d@ -f1)"
        g layout assign -z dev -c 10G "$node" >/dev/null
        g layout apply --version 1 >/dev/null
    fi

    if curl -fsS -o /dev/null -m 2 "http://127.0.0.1:3903/health" 2>/dev/null; then
        store_ok=1
    else
        say "garage        FAILED to become ready -- see $GARAGE_LOG"
    fi
fi

if [ "$store_ok" = 1 ] && [ -n "$GARAGE_BIN" ]; then
    # `key import`, not `key create`: create generates a GK... id that nothing
    # would know, and the documented `pytest -q` passes no environment. The
    # minimum lengths this pair satisfies are Garage's, measured 2026-10-04.
    g bucket info "$S3_BUCKET" >/dev/null 2>&1 || {
        g bucket create "$S3_BUCKET" >/dev/null
        say "garage        bucket $S3_BUCKET created"
    }
    g key info "$S3_ACCESS_KEY" >/dev/null 2>&1 \
        || g key import "$S3_ACCESS_KEY" "$S3_SECRET_KEY" -n dev-conftest --yes >/dev/null
    # --owner too, unlike the deployment's API key: the dev store has no
    # provisioning credential of its own and the CORS rule below needs it.
    g bucket allow --read --write --owner "$S3_BUCKET" --key "$S3_ACCESS_KEY" >/dev/null
    say "garage        bucket $S3_BUCKET ready, key $S3_ACCESS_KEY granted rwo"

    # **`*`, and only here.** The deployment gets one concrete origin, and
    # platform/garage/provision.sh refuses `*` outright -- but the two upload
    # tests in test_ui_browser.py serve the page from a random localhost port
    # and POST to another, so they are cross-origin in a container. They passed
    # under MinIO only because MinIO's own default is `*`. Garage has no
    # default, so without this they fail with "the browser blocked the upload".
    S3_ACCESS_KEY="$S3_ACCESS_KEY" S3_SECRET_KEY="$S3_SECRET_KEY" \
    S3_BUCKET="$S3_BUCKET" S3_REGION="$S3_REGION" \
    "$REPO_ROOT/platform/.venv/bin/python" - <<"PY" || true
import os

import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3", endpoint_url="http://127.0.0.1:9000",
    aws_access_key_id=os.environ["S3_ACCESS_KEY"],
    aws_secret_access_key=os.environ["S3_SECRET_KEY"],
    region_name=os.environ["S3_REGION"],
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)
s3.put_bucket_cors(Bucket=os.environ["S3_BUCKET"], CORSConfiguration={"CORSRules": [{
    "AllowedOrigins": ["*"], "AllowedMethods": ["GET", "HEAD", "POST"],
    "AllowedHeaders": ["*"], "MaxAgeSeconds": 3000,
}]})
print("garage        CORS '*' -- DEVELOPMENT ONLY, see this script's comment")
PY
fi

fi   # ------------------------------------------------------ end the store ----

# --- Optional extras -------------------------------------------------------
#
# Both skip loudly rather than failing, so they are reported and not installed.

# `mc` is MinIO's client and reaches its admin plane, which Garage does not
# have. The three service-account policy tests it gates are MinIO-only by
# construction; under Garage the equivalent assertions are the front's, in
# tests/test_object_front.py and platform/garage/conformance.py.
if [ "$OBJECT_STORE" = minio ] && command -v "${MC_BIN:-mc}" >/dev/null 2>&1; then
    say "mc            present"
elif [ "$OBJECT_STORE" = minio ]; then
    say "mc            absent -- service-account policy tests will skip"
else
    say "mc            not used with garage (no admin plane) -- those tests skip"
fi

if [ -d "${HOME}/.cache/ms-playwright" ]; then
    say "playwright    present"
else
    say "playwright    absent -- run 'playwright install chromium' for the XSS tests"
fi

say ""
# Name the store that is up. A developer who does not know which one answered
# cannot read a failure -- and the two differ in error shapes, which is the
# whole reason both paths exist.
if [ "$pg_ok" = 1 ] && [ "$store_ok" = 1 ]; then
    say "store:  $OBJECT_STORE on 127.0.0.1:9000"
    say "ready:  cd platform && .venv/bin/python -m pytest -q"
else
    say "NOT ready for the platform suite -- see above."
    say "sandboxd's suite needs none of this:"
    say "  platform/.venv/bin/python -m pytest sandboxd/tests -q"
fi