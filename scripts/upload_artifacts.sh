#!/usr/bin/env bash
# Upload pipeline outputs (scan, SBOM, SARIF, gate result, report) to the
# Artifactory generic repository, next to the image they describe:
#   $ART_GENERIC_REPO/$IMAGE_NAME/<rev>/<file>
# Each upload sends its SHA-256 so Artifactory rejects a corrupted transfer.
# Usage: upload_artifacts.sh <rev> <file>...
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -ge 2 ] || die "usage: $0 <rev> <file>..."
require_env ART_URL ART_TOKEN
require_cmd curl
REV="$1"
shift
base="${ART_URL%/}/artifactory/${ART_GENERIC_REPO:-generic-local}/${IMAGE_NAME:-devsecops-app}/${REV}"

uploaded=0
for file in "$@"; do
  if [ ! -f "$file" ]; then
    log "skip missing file: ${file}"
    continue
  fi
  name="$(basename "$file")"
  art_curl --request PUT \
    --header "X-Checksum-Sha256: $(sha256_of "$file")" \
    --upload-file "$file" \
    --output /dev/null \
    "${base}/${name}" || die "upload failed: ${name}"
  log "uploaded ${name}"
  uploaded=$((uploaded + 1))
done
log "uploaded ${uploaded} file(s) to ${ART_GENERIC_REPO:-generic-local}/${IMAGE_NAME:-devsecops-app}/${REV}/"
