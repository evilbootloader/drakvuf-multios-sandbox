#!/bin/sh
#
# Provision the analysis object store on Garage. Runbook 18, Part D.
#
# Replaces `platform/minio/provision.sh`, which provisioned MinIO -- archived
# upstream 2026-04-25 and carrying CVE-2026-97731 unfixed. Same contract: one
# idempotent script, with the reasoning next to each control rather than in a
# document, so there is a copy a test can exercise and a way to re-apply
# everything after a rebuild.
#
# **What moved, and it is not a detail.** MinIO's half of this was an IAM
# policy granting `s3:GetObject` and `s3:PutObject` and nothing else. Garage
# has no policy language: permissions are per key, per bucket, and `read`
# implies ListObjects while `write` implies DeleteObject, DeleteObjects and
# CopyObject (`src/api/s3/router.rs`). The capabilities `api-policy.json`
# withheld are therefore withheld by the TLS front instead -- see
# `objects.conf` in runbook 18 Part E, DECISION A2 -- and this script cannot
# assert them. `conformance.py` does, and this script ends by telling you to
# run it.
#
# **Idempotent.** Every step converges or reports what is already there, so a
# re-run after a partial failure is the recovery path rather than a hazard.
# Three measured behaviours make that non-obvious and are handled below:
# `bucket create` fails on an existing bucket, `key create` happily mints a
# SECOND key with the same name, and `bucket info`/`key info` exit 1 both when
# the thing is absent and when a name is ambiguous.
#
# Admin-plane credentials are used HERE and nowhere else. The `garage` CLI
# reaches the running server over RPC with the `rpc_secret` from its config
# file, so this must run as root on the platform DomU. The API gets a
# `read`+`write` key and never `owner`.
#
# Run on the platform DomU:
#
#     BROWSER_ORIGIN=https://sandbox.evilbootloader.com \
#     BUCKET_QUOTA=200GiB \
#     RETENTION_DAYS=30 \
#       /opt/platform/src/platform/garage/provision.sh
#
# POSIX sh: this project's shell scripts run under dash, and there is no
# reason for this one to differ. Checked with `dash -n`, `bash -n`,
# `shellcheck`.

set -eu

# `$0`, not `${BASH_SOURCE[0]}` -- the latter is empty under dash and would
# silently resolve the interpreter against $PWD. Issue #4 lost an afternoon to
# it, and `platform/minio/provision.sh` carries the same note.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

GARAGE_BIN=${GARAGE_BIN:-garage}
GARAGE_CONFIG=${GARAGE_CONFIG:-/etc/garage.toml}

# Garage's S3 API, which binds LOOPBACK only (runbook 18 Part C). The two
# bucket-level controls below are the only S3 calls this script makes, and
# both are PUTs that the front refuses on purpose -- so they go straight to
# the store, which is also why this script has to run on the DomU itself.
S3_ENDPOINT=${S3_ENDPOINT:-http://127.0.0.1:3900}

BUCKET=${S3_BUCKET:-analysis}
REGION=${S3_REGION:-eu-central-1}
API_KEY_NAME=${API_KEY_NAME:-objects-api}

# The owner key is EPHEMERAL: minted here, used for the two bucket-level PUTs,
# deleted on exit. A standing owner credential would be a second live secret
# nobody records, and the only things that need `owner` are these two calls.
# Named rather than random so an aborted run leaves something recognisable
# that the next run cleans up.
PROV_KEY_NAME=${PROV_KEY_NAME:-objects-provision-ephemeral}

# boto3 is the only client for `PutBucketCors` and
# `PutBucketLifecycleConfiguration`: the `garage` CLI has no command for
# either, and `mc` is the archived server's client. Resolved from this
# script's own location, like every other path in this repository.
PYTHON=${PYTHON:-$SCRIPT_DIR/../.venv/bin/python}

RETENTION_DAYS=${RETENTION_DAYS:-30}

die() { printf 'provision: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
g() { "$GARAGE_BIN" -c "$GARAGE_CONFIG" "$@"; }

# Exists-or-not for a bucket. `bucket info` exits 1 when the bucket is absent
# (measured 2026-10-03), so this is a question and not an error.
bucket_exists() { g bucket info "$BUCKET" >/dev/null 2>&1; }

# How many keys carry this NAME. Not `key info <name>`: that exits 1 both for
# "absent" and for "2 matching keys", and those two want opposite responses.
keys_named() {
  g key list 2>/dev/null | awk -v want="$1" 'NR > 1 && $3 == want { n++ } END { print n + 0 }'
}

key_id_of()     { g key info "$1" 2>/dev/null | awk '/^Key ID:/ { print $3 }'; }
key_secret_of() { g key info "$1" --show-secret 2>/dev/null | awk '/^Secret key:/ { print $3 }'; }

# --- preconditions --------------------------------------------------------
#
# Checked up front rather than discovered halfway through, because a run that
# stops after creating the bucket but before the lifecycle rule leaves a store
# that looks provisioned and has no retention.

command -v "$GARAGE_BIN" >/dev/null 2>&1 || die "$GARAGE_BIN is not on PATH"
[ -r "$GARAGE_CONFIG" ] || die "cannot read $GARAGE_CONFIG -- run this as root"
[ -x "$PYTHON" ] || die "no python at $PYTHON (set PYTHON=...)"
"$PYTHON" -c 'import boto3' 2>/dev/null \
  || die "$PYTHON cannot import boto3, which CORS and retention need"

# Both are decisions, not defaults, and defaulting either is precisely the
# failure issue #37 exists to fix: a store with no quota fills silently at the
# end of a spent analysis, and a store with a permissive origin lets any page
# a browser visits use a leaked presigned URL.
[ -n "${BROWSER_ORIGIN:-}" ] || die "BROWSER_ORIGIN is unset; it is the page's
  origin, e.g. https://sandbox.evilbootloader.com. There is no default."
[ -n "${BUCKET_QUOTA:-}" ] || die "BUCKET_QUOTA is unset, e.g. 200GiB. Size it
  below the data volume so the store refuses writes before the filesystem
  does -- a full filesystem surfaces as a truncated artifact."

# `*` is refused here even though the DEVELOPMENT store needs it: the two
# browser upload tests in platform/tests/test_ui_browser.py are cross-origin
# in a container and passed under MinIO only because MinIO's own default was
# `*`. That is scripts/dev-services.sh's business, not this script's, and a
# deployment that acquires `*` by accident should fail rather than warn.
case $BROWSER_ORIGIN in
  '*' | *' '*) die "BROWSER_ORIGIN must be one concrete origin, not '$BROWSER_ORIGIN'" ;;
esac

case $RETENTION_DAYS in
  '' | *[!0-9]*) die "RETENTION_DAYS must be a whole number of days, or 0" ;;
esac

# The region is part of the SigV4 signing scope, so a mismatch between the
# store and api.env fails every presigned URL with a 400 that discusses the
# authorization header and never mentions regions. MinIO hid this value behind
# `mc admin config get <alias> region` reporting empty for an env-set region;
# in Garage it is one line of the config file and can simply be read.
config_region=$(awk -F'"' '/^[[:space:]]*s3_region[[:space:]]*=/ { print $2; exit }' \
  "$GARAGE_CONFIG")
[ -n "$config_region" ] || die "no s3_region in $GARAGE_CONFIG"
[ "$config_region" = "$REGION" ] \
  || die "s3_region is '$config_region' in $GARAGE_CONFIG but S3_REGION is
  '$REGION'. These must agree, and api.env's S3_REGION must agree with both."

# A node with no layout accepts no writes, and the failure arrives later as a
# confusing 500 on the first upload rather than here. `NO ROLE ASSIGNED` is
# the string `garage status` prints for it (measured 2026-10-02).
# An `if`, not `cmd && die`: under `set -eu` the AND-list's status is grep's
# failure when there is no match, and relying on the exemption for a
# non-final `&&` operand is a subtlety nobody should have to recall here.
if g status | grep -q 'NO ROLE ASSIGNED'; then
  die "this node has no layout role, so it will accept no writes. Run
  \`garage layout assign\` and \`garage layout apply\` first -- runbook 18
  Part C."
fi

# --- the ephemeral owner key, and its cleanup -----------------------------

prov_created=
cleanup() {
  [ -n "$prov_created" ] || return 0
  printf '\n== removing the ephemeral owner key %s\n' "$PROV_KEY_NAME"
  g key delete "$prov_created" --yes >/dev/null 2>&1 \
    || printf 'WARNING: could not delete %s -- do it by hand\n' "$prov_created" >&2
}
trap cleanup EXIT

# --- the store ------------------------------------------------------------

step "bucket $BUCKET"
if bucket_exists; then
  printf 'exists\n'
else
  g bucket create "$BUCKET"
fi

step "quota $BUCKET_QUOTA"
# The real backstop against one job filling the store. `max_artifact_bytes`
# caps a single object, but `memdump` writes many small files and a worker may
# request tickets repeatedly, so nothing else bounds a job's total.
# `--max-objects` also exists and is deliberately not set: no decision has
# been taken about an object count, and an unexplained limit is worse than
# none.
g bucket set-quotas "$BUCKET" --max-size "$BUCKET_QUOTA" >/dev/null
g bucket info "$BUCKET" | sed -n '/Quotas/,+2p'

step "api key $API_KEY_NAME"
# `key create` does NOT converge: run twice, and there are two live keys with
# the same name and no way to tell which one api.env holds (measured
# 2026-10-03). Count first, and refuse rather than guess when the damage has
# already been done.
case $(keys_named "$API_KEY_NAME") in
  0) g key create "$API_KEY_NAME" >/dev/null
     printf 'created\n' ;;
  1) printf 'exists; reusing it\n' ;;
  *) die "there are several keys named '$API_KEY_NAME'. One of them is what
  api.env holds and this script cannot tell which. Resolve it by hand:
      $GARAGE_BIN -c $GARAGE_CONFIG key list
      $GARAGE_BIN -c $GARAGE_CONFIG key delete <the unused id> --yes" ;;
esac

api_id=$(key_id_of "$API_KEY_NAME")
[ -n "$api_id" ] || die "could not read the id of key '$API_KEY_NAME'"

# read+write, never owner: the API must not be able to change the bucket's
# CORS rule, its lifecycle rule, or delete the bucket. That is the one part of
# api-policy.json's shape Garage can still express.
g bucket allow --read --write "$BUCKET" --key "$api_id" >/dev/null
printf 'granted read+write (NOT owner)\n'

step "ephemeral owner key"
# A leftover from an aborted run is ours by name; remove it rather than
# accumulating credentials.
while [ "$(keys_named "$PROV_KEY_NAME")" != 0 ]; do
  stale=$(g key list | awk -v want="$PROV_KEY_NAME" 'NR > 1 && $3 == want { print $1; exit }')
  printf 'removing a leftover %s (%s)\n' "$PROV_KEY_NAME" "$stale"
  g key delete "$stale" --yes >/dev/null
done
g key create "$PROV_KEY_NAME" >/dev/null
prov_created=$(key_id_of "$PROV_KEY_NAME")
[ -n "$prov_created" ] || die "could not read the id of the ephemeral owner key"
g bucket allow --read --write --owner "$BUCKET" --key "$prov_created" >/dev/null
printf 'minted %s; it is deleted when this script exits\n' "$prov_created"

# --- the two controls only the S3 API can set -----------------------------

step "CORS -> $BROWSER_ORIGIN, and retention -> ${RETENTION_DAYS} days"
# Values go through the environment rather than being interpolated into the
# heredoc: the heredoc is quoted, so nothing in it is expanded by the shell,
# and a value containing a quote cannot reach the Python source.
prov_secret=$(key_secret_of "$PROV_KEY_NAME")
[ -n "$prov_secret" ] || die "could not read the ephemeral owner key's secret;
  \`key info --show-secret\` printed nothing matching 'Secret key:'"

S3_ENDPOINT="$S3_ENDPOINT" \
GARAGE_ACCESS_KEY="$prov_created" \
GARAGE_SECRET_KEY="$prov_secret" \
S3_BUCKET="$BUCKET" \
S3_REGION="$REGION" \
BROWSER_ORIGIN="$BROWSER_ORIGIN" \
RETENTION_DAYS="$RETENTION_DAYS" \
"$PYTHON" - <<'PY'
import os

import boto3
from botocore.config import Config

bucket = os.environ["S3_BUCKET"]
s3 = boto3.client(
    "s3", endpoint_url=os.environ["S3_ENDPOINT"],
    aws_access_key_id=os.environ["GARAGE_ACCESS_KEY"],
    aws_secret_access_key=os.environ["GARAGE_SECRET_KEY"],
    region_name=os.environ["S3_REGION"],
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)

# CORS is PER BUCKET here, where MinIO had only a server-wide
# `cors_allow_origin` -- so the trap that made an env-set value win silently
# over the config store, invisibly to `mc admin config get`, is gone with it.
#
# Still defence in depth rather than the primary control: since #37 the
# browser reaches the store at /analysis/* on the API's own hostname, so the
# upload is same-origin and needs no CORS at all. It matters because a store
# that reflected any origin would let a page at attacker.example holding a
# LEAKED presigned URL read the response. Measured against Garage 2026-10-03:
# a preflight from any other origin is refused outright with 403, and a real
# response carries no Allow-Origin at all -- stricter than MinIO's default,
# which reflected the origin WITH Allow-Credentials: true.
#
# GET and HEAD alongside POST because the browser both uploads and, for a
# direct artifact read, fetches; the method list is still far tighter than
# MinIO's server-wide origin allowance, which constrained no method.
s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={"CORSRules": [{
    "AllowedOrigins": [os.environ["BROWSER_ORIGIN"]],
    "AllowedMethods": ["GET", "HEAD", "POST"],
    "AllowedHeaders": ["*"],
    "MaxAgeSeconds": 3000,
}]})
print("cors:", s3.get_bucket_cors(Bucket=bucket)["CORSRules"])

# **Lifecycle expiry, not object-lock retention.** The two are opposites and
# share a word: object lock PREVENTS deletion for a period, which is why
# conformance.py asserts it absent. This DELETES after one. Garage runs the
# expiry itself, daily at midnight (`src/model/s3/lifecycle_worker.rs`), so
# the API needs no destructive capability for it -- which is what keeps
# DeleteObject out of what the front allows.
#
# One rule over the whole bucket rather than a shorter period for `samples/`
# and a longer one for `results/`. That split is tempting -- drop the malware
# sooner, keep the evidence longer -- and it does not work:
# `results/<job_id>/extracted/` is malware too, S3 lifecycle prefixes are
# literal rather than globs, and `results/*/extracted/` cannot be expressed. A
# longer results period would keep dropped executables longer than the sample
# they came from.
#
# A PUT replaces the whole configuration, which is what makes this
# idempotent -- there is no rule-stacking hazard of the kind that made MinIO's
# `mc ilm rule add` the wrong verb.
days = int(os.environ["RETENTION_DAYS"])
if days > 0:
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket, LifecycleConfiguration={"Rules": [{
            "ID": "sandbox-platform-retention", "Status": "Enabled",
            "Filter": {"Prefix": ""}, "Expiration": {"Days": days},
        }]})
    # Read it back rather than trusting the absence of a traceback: a rule
    # that was rejected and a rule that was never installed look identical
    # from the outside, and the difference is whether this store has a
    # retention policy at all.
    print("ilm: ", s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"])
    print("\nRETENTION_DAYS must match RETENTION_DAYS in api.env, or the job")
    print("detail view will offer download links for objects Garage has removed.")
else:
    s3.delete_bucket_lifecycle(Bucket=bucket)
    print("ilm:  disabled: objects are kept indefinitely, and nothing reclaims")
    print("      the store but the quota refusing writes.")
PY

# --- what the operator needs ----------------------------------------------

# Deleted HERE rather than left to the trap, so the state dump below shows the
# store as this script will actually leave it. An ephemeral key still listed
# against the bucket reads exactly like a standing owner credential, which is
# the thing it exists not to be. The trap stays as the safety net for an abort
# before this point.
cleanup
prov_created=

step "state"
g bucket info "$BUCKET"

step "done"
cat /etc/sandbox-platform/api.env <EOF
  S3_ACCESS_KEY=$api_id
  S3_SECRET_KEY=$(key_secret_of "$API_KEY_NAME")
EOF
