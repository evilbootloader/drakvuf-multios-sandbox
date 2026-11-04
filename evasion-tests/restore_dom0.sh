#!/usr/bin/env bash
# Puts dom0 back as make xen left it after a search that could not do it itself: dom0 was
# unreachable when the search ended, this machine went down, or the search was killed. The
# sources a variant overwrote (REMOTE_STATE/orig), the Xen package make xen installed
# (REMOTE_STATE/known-good) and Xen as the GRUB default entry, booted (search_common.sh,
# search_end). Nothing to put back is fine: it only reboots dom0 into Xen if it is not there.
#
# Usage: ./restore_dom0.sh    (same site.conf as the searches; reboots dom0 up to twice)
set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SITE_CONF=${SITE_CONF:-$SCRIPT_DIR/site.conf}
# shellcheck source=/dev/null
[[ ! -e "$SITE_CONF" ]] || source "$SITE_CONF"
source "$SCRIPT_DIR/search_common.sh"

RESULTS=${RESULTS:-$RESULTS_BASE/restore/$(date '+%Y%m%d-%H%M%S')}
[[ -r "$SSH_KEY" ]] || die "Missing SSH key $SSH_KEY"
mkdir -p "$RESULTS"
rsh true || die "Cannot reach $DOM0"
search_end
