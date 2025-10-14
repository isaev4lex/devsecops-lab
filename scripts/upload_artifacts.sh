#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/upload_artifacts.sh <rev> <files...>
# Example:
#   ./scripts/upload_artifacts.sh 20251014171516 trivy.json sbom/sbom.cdx.json reports/report.md

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "ERROR: $name is not set" >&2
    exit 1
  fi
}

require_env "ART_URL"
require_env "ART_TOKEN"

if [ $# -lt 2 ]; then
  echo "Usage: $0 <rev> <files...>" >&2
  exit 1
fi

REV="$1"; shift
BASE="${ART_URL%/}/artifactory/generic-local/devsecops-app/${REV}"

echo "Uploading to: ${BASE}"
uploaded=0
for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "WARN: skip missing file: $f" >&2
    continue
  fi
  name="$(basename "$f")"
  dest="${BASE}/${name}"
  echo " -> ${name}"
  curl -sS -f -X PUT -H "Authorization: Bearer ${ART_TOKEN}" \
       --upload-file "$f" "$dest" >/dev/null
  uploaded=$((uploaded+1))
done

echo "Done. Uploaded files: ${uploaded}"
