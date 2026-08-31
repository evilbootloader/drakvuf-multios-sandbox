#!/bin/sh
# Bring up the services `platform/tests` needs, in a development container.
#
# **This is not a deployment script.** It exists because `CLAUDE.md` and
# `README.md` both name `cd platform && .venv/bin/python -m pytest -q` as a
# standard command, and in a fresh container that command cannot run: the
# Postgres cluster is installed but down, and MinIO is not installed at all.
# A documented command that fails is worse than an undocumented one, because
# the failure looks like a defect in the code under test.
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
MINIO_DATA="${MINIO_DATA:-/tmp/minio-data}"
MINIO_LOG="${MINIO_LOG:-/tmp/minio.log}"

# These four MUST match `platform/tests/conftest.py`'s defaults. It reads the
# environment once, at import, so a mismatch here is not a warning -- it is a
# test failure attributed to whatever the test was actually about.
S3_ACCESS_KEY="devroot"
S3_SECRET_KEY="devrootpass"
S3_BUCKET="analysis"
S3_REGION="eu-central-1"

pg_ok=0
minio_ok=0

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

# --- MinIO -----------------------------------------------------------------
#
# MINIO_SITE_REGION is the one that bites. The region is part of the SigV4
# signing scope, so a MinIO with no region set rejects every presigned URL the
# API generates -- with a 403 that discusses signatures and never mentions
# regions. Do not probe it with `mc admin config get local region`, which
# reports empty for an env-set value; use `... get local site`.

MINIO_BIN="${MINIO_BIN:-$(command -v minio || true)}"

if curl -fsS -o /dev/null -m 2 "http://127.0.0.1:9000/minio/health/live" 2>/dev/null; then
    say "minio         already up on 127.0.0.1:9000"
    minio_ok=1
elif [ -z "$MINIO_BIN" ]; then
    say "minio         NOT INSTALLED -- tests needing object storage will fail"
    say "              curl -fsSLo ~/.local/bin/minio \\"
    say "                https://dl.min.io/server/minio/release/linux-amd64/minio"
    say "              chmod +x ~/.local/bin/minio"
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
        then minio_ok=1; break; fi
        n=$((n + 1))
        sleep 1
    done
    [ "$minio_ok" = 1 ] || say "minio         FAILED to come up -- see $MINIO_LOG"
fi

# The bucket is created here because nothing else does. `conftest.py` writes
# objects into it directly and `platform/minio/provision.sh` -- which would
# create it -- needs `mc` and is written for the deployment, not for tests.
if [ "$minio_ok" = 1 ] && [ -x "$REPO_ROOT/platform/.venv/bin/python" ]; then
    S3_ACCESS_KEY="$S3_ACCESS_KEY" S3_SECRET_KEY="$S3_SECRET_KEY" \
    S3_BUCKET="$S3_BUCKET" S3_REGION="$S3_REGION" \
    "$REPO_ROOT/platform/.venv/bin/python" - <<'PY' || true
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

# --- Optional extras -------------------------------------------------------
#
# Both skip loudly rather than failing, so they are reported and not installed.

if command -v "${MC_BIN:-mc}" >/dev/null 2>&1; then
    say "mc            present"
else
    say "mc            absent -- service-account policy tests will skip"
fi

if [ -d "${HOME}/.cache/ms-playwright" ]; then
    say "playwright    present"
else
    say "playwright    absent -- run 'playwright install chromium' for the XSS tests"
fi

say ""
if [ "$pg_ok" = 1 ] && [ "$minio_ok" = 1 ]; then
    say "ready:  cd platform && .venv/bin/python -m pytest -q"
else
    say "NOT ready for the platform suite -- see above."
    say "sandboxd's suite needs none of this:"
    say "  platform/.venv/bin/python -m pytest sandboxd/tests -q"
fi