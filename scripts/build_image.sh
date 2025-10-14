#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "ERROR: $name is not set" >&2
    exit 1
  fi
}

require_env "IMG"
require_env "REV"

echo "Building image: ${IMG}:${REV}"

docker build \
  -f app/Dockerfile \
  -t "${IMG}:${REV}" \
  --label "org.opencontainers.image.title=devsecops-app" \
  --label "org.opencontainers.image.revision=${REV}" \
  --label "org.opencontainers.image.source=$(git config --get remote.origin.url || echo local)" \
  --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  .

echo "Image built: ${IMG}:${REV}"
echo "${REV}" > .rev
echo "Saved revision to .rev: ${REV}"