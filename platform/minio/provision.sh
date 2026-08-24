#!/bin/sh
#
# Provision the analysis object store. Issue #37 (DRAFT-044).
#
# Replaces the hand-run `mc` blocks that lived in runbook step 15. The policy
# was a heredoc inside a document, which meant there was no copy a test could
# load and no way to re-apply it after a rebuild -- see api-policy.json and
# tests/test_objects.py, which assert what this grants and what it withholds.
#
# **Idempotent.** Every step either converges or reports what is already
# there, so a re-run after a partial failure is the recovery path rather than
# a hazard. The one exception is the service account: an existing one has its
# policy updated in place, because minting a second would leave a live
# credential nobody recorded.
#
# Root credentials are used HERE and nowhere else. They create the bucket, the
# policy and the service account, and must not appear in any application
# config -- the API gets the service account only.
#
# Run on the platform LXC:
#
#     set -a; . /etc/minio/minio.env; set +a
#     BROWSER_ORIGIN=https://sandbox.evilbootloader.com \
#     BUCKET_QUOTA=200GiB \
#       /root/drakvuf-multios-sandbox/platform/minio/provision.sh
#
# POSIX sh: this project's shell scripts run under dash, and there is no
# reason for this one to differ. Checked with `dash -n`, `bash -n`,
# `shellcheck`.

set -eu

# `$0`, not `${BASH_SOURCE[0]}` -- the latter is empty under dash and would
# silently resolve the policy against $PWD. Issue #4 lost an afternoon to it.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

ALIAS=${MINIO_ALIAS:-local}
ENDPOINT=${MINIO_ENDPOINT:-https://127.0.0.1:9000}
BUCKET=${S3_BUCKET:-analysis}
POLICY=${API_POLICY:-$SCRIPT_DIR/api-policy.json}
# Exactly 20 characters, which is MinIO's maximum for an access key (3..20).
# Renaming it to anything longer fails with "access key length should be
# between 3 and 20" at `svcacct add` -- there is no margin left in this string.
API_KEY=${API_ACCESS_KEY:-sandbox-platform-api}
CA=${MINIO_CA:-/etc/sandbox-platform/tls/ca.crt}

die() { printf 'provision: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }

# --- preconditions --------------------------------------------------------
#
# Checked up front rather than discovered halfway through, because a run that
# stops after creating the bucket but before the policy leaves a store that
# looks provisioned and is not.

command -v mc >/dev/null 2>&1 || die "mc is not on PATH"
[ -f "$POLICY" ] || die "policy file not found: $POLICY"
[ -n "${MINIO_ROOT_USER:-}" ] || die "MINIO_ROOT_USER is unset (source minio.env)"
[ -n "${MINIO_ROOT_PASSWORD:-}" ] || die "MINIO_ROOT_PASSWORD is unset"

# Both are decisions, not defaults. Defaulting either is precisely the failure
# this issue exists to fix: MinIO's own CORS default is `*`, and a store with
# no quota fills silently at the end of a spent analysis.
[ -n "${BROWSER_ORIGIN:-}" ] || die "BROWSER_ORIGIN is unset; it is the page's
  origin, e.g. https://sandbox.evilbootloader.com. There is no default because
  MinIO's own is '*', which lets any page a browser visits use a leaked
  presigned URL."
[ -n "${BUCKET_QUOTA:-}" ] || die "BUCKET_QUOTA is unset, e.g. 200GiB. Size it
  below the data volume so the store refuses writes before the filesystem
  does -- a full filesystem surfaces as a truncated artifact."

case $BROWSER_ORIGIN in
  '*'|*' '*) die "BROWSER_ORIGIN must be one concrete origin, not '$BROWSER_ORIGIN'" ;;
esac

# The policy names its bucket in an ARN and cannot interpolate. Rather than
# template it, refuse the mismatch: a policy granting rights on a bucket other
# than the one being provisioned is the kind of thing that reads fine.
grep -q "arn:aws:s3:::${BUCKET}/\*" "$POLICY" \
  || die "$POLICY does not grant on bucket '$BUCKET'"

# mc reads extra CAs from its config dir. The LAN certificate is signed by the
# internal CA (#39), so without this every call fails certificate validation
# and the message blames the endpoint rather than the trust store.
if [ -f "$CA" ]; then
  mc_certs="${MC_CONFIG_DIR:-$HOME/.mc}/certs/CAs"
  mkdir -p "$mc_certs"
  cp "$CA" "$mc_certs/sandbox-platform-ca.crt"
fi

step "alias -> $ENDPOINT"
mc alias set "$ALIAS" "$ENDPOINT" "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
printf 'ok\n'

step "bucket $BUCKET"
mc mb --ignore-existing "$ALIAS/$BUCKET"

# --- the controls ---------------------------------------------------------

step "anonymous access"
# MinIO's default is already private; set it anyway so the posture is declared
# rather than inherited. This is the baseline every other control rests on.
mc anonymous set none "$ALIAS/$BUCKET" >/dev/null
mc anonymous get "$ALIAS/$BUCKET"

step "versioning"
# Off, deliberately: versioning a store of large write-once artifacts
# multiplies storage for a rollback nobody performs. Asserted rather than
# suspended -- turning it off would silently discard existing versions, which
# is a data decision and not this script's to make.
version_state=$(mc version info "$ALIAS/$BUCKET" 2>&1)
printf '%s\n' "$version_state"
case $version_state in
  *un-versioned*) : ;;
  *) die "versioning is enabled on $BUCKET; refusing to change it here" ;;
esac

step "object lock"
# Off, and this one matters more than versioning. Object lock would make
# retention UNDECIDABLE later -- you cannot delete what is locked, and
# retention is explicitly still open (DRAFT-022). It can only be set at bucket
# creation, so this can only ever be an assertion.
if mc retention info --default "$ALIAS/$BUCKET" >/dev/null 2>&1; then
  die "object lock is enabled on $BUCKET; retention could not be designed later"
fi
printf 'not enabled\n'

step "quota $BUCKET_QUOTA"
# The real backstop against one job filling the store. `max_artifact_bytes`
# caps a single object, but `memdump` writes many small files and a worker may
# request tickets repeatedly, so nothing else bounds a job's total.
mc quota set "$ALIAS/$BUCKET" --size "$BUCKET_QUOTA" >/dev/null
mc quota info "$ALIAS/$BUCKET"

step "retention: expire after ${RETENTION_DAYS:-30} days"
# **Lifecycle expiry, not object-lock retention.** The two are opposites and
# share a word: object lock PREVENTS deletion for a period, which is why it is
# asserted off above. This DELETES after one.
#
# One rule over the whole bucket rather than a shorter period for `samples/`
# and a longer one for `results/`. That split is tempting -- drop the malware
# sooner, keep the evidence longer -- and it does not work:
# `results/<job_id>/extracted/` is malware too, S3 lifecycle prefixes are
# literal rather than globs, and `results/*/extracted/` cannot be expressed. A
# longer results period would keep dropped executables longer than the sample
# they came from. Tagging extracted artifacts at upload would allow the split;
# that is a change to the worker contract and is not this issue's.
#
# `import` rather than `add`: add mints a fresh rule ID per call, so re-running
# this script would stack duplicates. import replaces the whole configuration,
# which is what makes this step idempotent.
#
# **The API is still delete-less, and that is the point.** MinIO does the
# deleting on its own schedule, so retention costs the service account no
# destructive capability -- `DeleteObject` stays absent from api-policy.json.
retention_days=${RETENTION_DAYS:-30}
if [ "$retention_days" -gt 0 ] 2>/dev/null; then
  printf '{"Rules":[{"ID":"sandbox-platform-retention","Status":"Enabled",'\
'"Filter":{"Prefix":""},"Expiration":{"Days":%s}}]}\n' "$retention_days" \
    | mc ilm rule import "$ALIAS/$BUCKET"
  mc ilm rule ls "$ALIAS/$BUCKET"
  printf '\nRETENTION_DAYS must match RETENTION_DAYS in api.env, or the job\n'
  printf 'detail view will offer download links for objects MinIO has removed.\n'
else
  mc ilm rule rm --all --force "$ALIAS/$BUCKET" >/dev/null 2>&1 || true
  printf 'disabled: objects are kept indefinitely, and nothing reclaims the\n'
  printf 'store but the quota refusing writes.\n'
fi

step "CORS -> $BROWSER_ORIGIN"
# Server-wide, because per-bucket CORS does not exist on this build: both
# `mc cors set` and boto3's put_bucket_cors return NotImplemented, checked
# 2026-08-24 against RELEASE.2025-09-07.
#
# Applied through the config store rather than minio.env, and that is not
# arbitrary. It takes effect immediately with no restart (verified), and an
# env-set value would WIN SILENTLY over this one while being invisible to
# `mc admin config get` -- exactly the trap that made MINIO_SITE_REGION look
# unset for two days. Set it here or in minio.env, never both.
mc admin config set "$ALIAS" api cors_allow_origin="$BROWSER_ORIGIN" >/dev/null
printf 'cors_allow_origin=%s\n' \
  "$(mc admin config get "$ALIAS" api 2>/dev/null | tr ' ' '\n' \
     | sed -n 's/^cors_allow_origin=//p')"

step "service account $API_KEY"
# Fixed access key so re-running converges instead of minting a second live
# credential. Deliberately absent from the policy: no ListBucket, so a
# compromised API cannot enumerate a store of live malware, and no
# DeleteObject, because nothing in the design deletes an artifact and the
# capability should not exist until retention grants it.
if mc admin user svcacct info "$ALIAS" "$API_KEY" >/dev/null 2>&1; then
  mc admin user svcacct edit "$ALIAS" "$API_KEY" --policy "$POLICY" >/dev/null
  printf 'exists; policy re-applied from %s\n' "$POLICY"
  printf 'secret not shown -- it is not recoverable. To replace it:\n'
  printf '  mc admin user svcacct edit %s %s --secret-key <new>\n' "$ALIAS" "$API_KEY"
else
  # Exactly 40 characters, MinIO's maximum for a service-account secret
  # (8..40; it rejects longer with "secret key length should be between 8 and
  # 40", measured 2026-08-24 -- `-hex 24` produces 48 and fails).
  #
  # base64 rather than hex, because the limit is on CHARACTERS and hex packs
  # only 4 bits into each: `-hex 20` would also be 40 characters but carry 160
  # bits, where 30 random bytes in base64 carry 240 in the same space. That is
  # also exactly the length and alphabet of a real AWS secret access key.
  #
  # 30 bytes divides by 3, so there is no `=` padding, and base64 contains no
  # `$` -- both matter because this value is pasted into api.env, which
  # systemd reads as an EnvironmentFile and expands `$` in.
  secret=$(openssl rand -base64 30)
  mc admin user svcacct add "$ALIAS" "$MINIO_ROOT_USER" \
    --access-key "$API_KEY" --secret-key "$secret" \
    --policy "$POLICY" --name "sandbox-platform-api" \
    --description "Analysis API (#37). GetObject/PutObject on $BUCKET only." \
    >/dev/null
  printf 'created. These go into /etc/sandbox-platform/api.env and are NOT\n'
  printf 'recoverable afterwards:\n\n'
  printf '  S3_ACCESS_KEY=%s\n  S3_SECRET_KEY=%s\n' "$API_KEY" "$secret"
fi

step "region"
# `mc admin config get <alias> region` reports EMPTY for an env-provided value
# and is not a probe -- it is what made MINIO_SITE_REGION look unset. An
# env-set region appears as a commented line under `site`, and the behavioural
# check is that a wrong-region signature is refused (tests/test_objects.py).
mc admin config get "$ALIAS" site 2>/dev/null | sed -n 's/^# *//p' | grep REGION \
  || printf 'no MINIO_SITE_REGION in the environment; check minio.env\n'

printf '\n== done. S3_REGION in api.env must match the region above.\n'
