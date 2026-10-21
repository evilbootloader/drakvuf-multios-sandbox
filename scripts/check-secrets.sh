#!/bin/sh
# Scan for secrets before anything reaches git history.
#
# **Why this exists, and why it is not just TruffleHog.** TruffleHog detects
# *known credential formats* -- AWS keys, GitHub tokens, Stripe keys. It has no
# detector for this project's own secrets, and a clean TruffleHog run says
# nothing about them:
#
#   * the Cloudflare Access team domain and AUD, which name the tenant
#   * WORKER_TOKEN, the Dom0 -> platform bearer token
#   * MinIO root and service-account credentials
#   * the PBS encryption key and its fingerprint
#
# That is not hypothetical. On 2026-08-31 TruffleHog reported zero findings
# across the whole history and the whole tree, while `platform-domu.md` --
# parked at the repository root, awaiting commit -- carried the live Access team
# domain in three places. Runbook 08 had redacted the same value; this file had
# never been through that pass. So this script runs both: TruffleHog for the
# generic half, and a project-specific pass for the half only we know about.
#
#     scripts/check-secrets.sh            # working tree + git history
#     scripts/check-secrets.sh --tree     # working tree only, faster
#
# **History is the reason to run it before pushing, not after.** A secret in a
# pushed commit stays in history after the file is fixed; the remedy is a
# rewrite and a credential rotation, not an edit.
#
# Exits non-zero on any finding.

set -eu

# $0, never ${BASH_SOURCE[0]} -- this runs under dash as a git hook, where the
# bash-only form evaluates empty WITHOUT failing and silently turns the
# repository root into $PWD.
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd -- "$REPO_ROOT"

MODE="${1:-all}"
FOUND=0

note() { printf '%s\n' "$*"; }
fail() { printf '%s\n' "$*" >&2; FOUND=1; }

# ---------------------------------------------------------------------------
# 1. TruffleHog -- the generic half
# ---------------------------------------------------------------------------

if command -v trufflehog >/dev/null 2>&1; then
    TH=trufflehog
elif [ -x "$HOME/.local/bin/trufflehog" ]; then
    TH="$HOME/.local/bin/trufflehog"
else
    TH=""
fi

if [ -z "$TH" ]; then
    # **Reported, not fatal.** A missing scanner must not block a commit, or it
    # gets bypassed with --no-verify and then nothing runs at all. The
    # project-specific pass below still executes and still fails on a match.
    note "trufflehog: NOT INSTALLED -- generic credential detection skipped."
    note "  Install it (no package manager needed):"
    note "    V=\$(curl -fsSL https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \\"
    note "        | grep -m1 '\"tag_name\"' | sed 's/.*\"v\\([^\"]*\\)\".*/\\1/')"
    note "    curl -fsSL \"https://github.com/trufflesecurity/trufflehog/releases/download/v\$V/trufflehog_\${V}_linux_amd64.tar.gz\" \\"
    note "        | tar xz -C \"\$HOME/.local/bin\" trufflehog"
else
    EXCLUDES="$(mktemp)"
    THOUT="$(mktemp)"
    # Every line below is compiled as a regex, comments included, so explain an
    # exclusion here rather than there.
    #
    # misc/Artifacts/source-manifest.xml is the BlissOS build's repo manifest:
    # 1,488 public git revisions and nothing else. One of them sits on a line
    # naming the `ag-github` remote, and its first 20 hex digits read as a GitHub
    # OAuth client id -- 14 unverified GitHubOauth2 hits on 2026-10-21, every one
    # line 226. The history scan does not flag it.
    cat > "$EXCLUDES" <<'EOF'
^\.git/
^platform/\.venv/
^\.venv/
^profiles/
^state/
^tls/
node_modules/
__pycache__/
\.pyc$
# git-ignored and enormous: two BlissOS installer ISOs live in misc/.
# Excluded for time, not coverage -- *.iso is in .gitignore, so git cannot
# take them however carefully they are scanned.
\.iso$
^misc/Artifacts/source-manifest\.xml$
EOF

    # What was found, as detector and file:line -- never the value. CI runs this
    # too, and a real secret must not be copied into its log on the way to being
    # reported. The "Re-run for detail" this replaces named $EXCLUDES, which the
    # trap below had deleted by the time anyone ran it, so the finding was never
    # shown at all.
    report() {
        sed -n \
            -e 's/.*"commit":"\([0-9a-f]*\)".*"file":"\([^"]*\)".*"line":\([0-9]*\).*"DetectorName":"\([^"]*\)".*/    \4  \2:\3  commit \1/p' \
            -e 's/.*"file":"\([^"]*\)".*"line":\([0-9]*\).*"DetectorName":"\([^"]*\)".*/    \3  \1:\2/p' \
            "$THOUT" | sort -u >&2
    }

    # --fail exits 183 on a finding. Anything else non-zero is trufflehog itself
    # failing, which used to be reported as a secret too.
    trufflehog_result() {
        case "$1" in
            0) ;;
            183) fail "SECRET DETECTED in $2:"; report ;;
            *) fail "trufflehog FAILED (exit $1) scanning $2 -- it was not checked." ;;
        esac
    }

    note "trufflehog: scanning the working tree..."
    rc=0
    "$TH" filesystem . --exclude-paths="$EXCLUDES" \
        --results=verified,unknown --no-update --fail --json >"$THOUT" 2>/dev/null || rc=$?
    trufflehog_result "$rc" "the working tree"

    if [ "$MODE" != "--tree" ]; then
        note "trufflehog: scanning git history..."
        rc=0
        "$TH" git "file://$REPO_ROOT" --exclude-paths="$EXCLUDES" \
            --results=verified,unknown --no-update --fail --json >"$THOUT" 2>/dev/null || rc=$?
        trufflehog_result "$rc" "git history"
        [ "$rc" -ne 183 ] ||
            fail "  A secret already in history needs a rewrite AND rotation, not an edit."
    fi
fi

# ---------------------------------------------------------------------------
# 2. Project-specific patterns -- the half TruffleHog cannot know
# ---------------------------------------------------------------------------
#
# Each pattern is paired with a placeholder pattern that is allowed, so a
# deliberately redacted example does not fail the gate. Redact using the
# convention runbook 08 established: the literal REDACTED.
#
# **Scope is exactly what git would take**: tracked files plus untracked ones
# that are not ignored. Not a hand-maintained exclude list -- this respects
# .gitignore for free, so `profiles/`, `state/`, `tls/` and `.claude/` are out
# of scope because git already refuses them.
#
# That is also the correct semantic. The question is not "is there a secret on
# this disk" but "would a secret reach the repository", and the first version of
# this script answered the wrong one: it flagged `"kdf"` inside
# `profiles/android.json`, a LibVMI kernel-symbol table that is millions of
# lines long, untracked, and can never be committed.

note "project patterns: scanning what git would take..."

# Values that match a pattern above and are deliberately public. Each is
# non-secret *by construction*, not by assertion:
#
#   REDACTED           the project's redaction convention (runbook 08 set it)
#   <TEAM> <AUD>       placeholders in a documented command
#   EXAMPLE example.com  RFC 2606 / illustrative
#   devrootkey devrootpassphrase
#                        the development container's and CI's throwaway object
#                        store credentials, defined in scripts/dev-services.sh
#                        and in .github/workflows/static-checks.yml. They
#                        authenticate to a store that is destroyed with the job
#                        and is never reachable off localhost. The lengths are
#                        Garage's minimums (8 and 16), not a preference.
#
# **Add to this list only for a value that cannot be a secret anywhere.** A
# value that is merely "not secret right now" belongs redacted instead.
ALLOWED='REDACTED|<TEAM>|<AUD>|EXAMPLE|example\.com|xxxx|devrootkey|devrootpassphrase'

FILES="$(mktemp)"
trap 'rm -f "$FILES" "${EXCLUDES:-}" "${THOUT:-}"' EXIT INT TERM
# NUL-separated: filenames here contain spaces on purpose -- `benign sample.sh`
# is a deliberate test case for the hostile-filename path.
git ls-files --cached --others --exclude-standard -z | tr '\0' '\n' > "$FILES"

scan() {
    label="$1"
    pattern="$2"
    hits="$(while IFS= read -r f; do
                [ -f "$f" ] || continue
                # This script contains every pattern it searches for.
                case "$f" in scripts/check-secrets.sh) continue ;; esac
                grep -InHE "$pattern" -- "$f" 2>/dev/null || true
            done < "$FILES" \
            | grep -vE "$ALLOWED" || true)"
    if [ -n "$hits" ]; then
        fail ""
        fail "SECRET PATTERN: $label"
        printf '%s\n' "$hits" | sed 's/^/    /' >&2
    fi
}

# Cloudflare Access tenant. Not a credential, but it names the tenant and is
# the login surface; runbook 08 redacts it, so everything else must too.
scan "Cloudflare Access team domain" \
     '[a-z0-9]+-[a-z0-9]+-[a-z0-9]{4,8}\.cloudflareaccess\.com'

# The Access application audience tag, 64 hex.
scan "Cloudflare Access AUD" \
     'ACCESS_AUD[=: ]+[0-9a-f]{32,}'

# Bearer token Dom0 presents to the platform.
scan "WORKER_TOKEN value" \
     'WORKER_TOKEN[=: ]+[A-Za-z0-9_.-]{16,}'

# Object-store credentials.
#
# `["'\'']?` is not cosmetic. The first version required the value to start
# immediately after `=` or `:`, so `S3_SECRET_KEY="realsecret"` did not match
# while `S3_SECRET_KEY: realsecret` did -- it caught the CI workflow's
# throwaway value and would have missed a real one in quotes. Found because the
# two spellings disagreed, not because a real secret was ever there.
scan "MinIO / S3 secret" \
     '(MINIO_ROOT_PASSWORD|S3_SECRET_KEY|MINIO_SECRET_KEY|MINIO_ROOT_USER)[=:][[:space:]]*["'\'']?[A-Za-z0-9/+_-]{8,}'

# Garage's two server-side secrets, which live in /etc/garage.toml. Runbook 18
# prints both while provisioning, and its EVIDENCE blocks are exactly where a
# pasted config file would land.
#
# TOML spelling only (`key = "value"`), because that is the file they appear
# in; the environment forms GARAGE_RPC_SECRET and GARAGE_ADMIN_TOKEN are
# caught by the generic pass when trufflehog is installed.
scan "Garage rpc_secret / admin_token" \
     '(rpc_secret|admin_token|metrics_token)[[:space:]]*=[[:space:]]*["'\''][A-Za-z0-9/+=_-]{16,}'

# A Garage S3 access key is `GK` + 24 hex, and its SECRET is 64 hex with
# nothing to name it -- so the id is what is detectable, and finding one means
# a credential pair was probably pasted together. `provision.sh` prints them
# adjacently, which is the realistic accident.
scan "Garage access key id" \
     'GK[0-9a-f]{24}'

# Private keys of any kind. `tls/` is untracked and excluded above; this catches
# one pasted into a runbook.
scan "private key block" \
     '-----BEGIN [A-Z ]*PRIVATE KEY-----'

# PBS encryption key material. Losing this loses every backup; publishing it
# loses their confidentiality.
#
# Matches the byte-array shape a `encryption-key.json` actually has, not the
# bare word "kdf" -- that appeared in a LibVMI kernel-symbol table and was the
# first version's only finding.
scan "PBS encryption key material" \
     '"(data|salt)"[[:space:]]*:[[:space:]]*\[[0-9]{1,3},[0-9, ]{40,}'

# ---------------------------------------------------------------------------

if [ "$FOUND" -ne 0 ]; then
    printf '\n%s\n' "REFUSING: fix the finding above before committing." >&2
    printf '%s\n' "Redact with the literal REDACTED, as docs/runbooks/08-*.md does." >&2
    exit 1
fi

note "no secrets found"
exit 0