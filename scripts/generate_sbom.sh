#!/usr/bin/env bash
# Generate a CycloneDX JSON SBOM for a saved image tarball with Syft.
# Packages only: per-file entries are switched off, they add thousands of
# components without adding package information.
# Usage: generate_sbom.sh <image.tar> <output.cdx.json> [name] [version]
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -ge 2 ] || die "usage: $0 <image.tar> <output.cdx.json> [name] [version]"
TAR="$1"
OUT_FILE="$2"
NAME="${3:-${IMAGE_NAME:-devsecops-app}}"
VERSION="${4:-${REV:-unknown}}"
require_cmd docker jq
[ -s "$TAR" ] || die "image tarball not found: ${TAR} (run 'make build' first)"

log "generating SBOM for ${TAR} with ${SYFT_IMAGE%%@*}"
run_to_file "$OUT_FILE" docker run "${TOOL_RUN_FLAGS[@]}" \
  --env HOME=/tmp \
  --env SYFT_CHECK_FOR_APP_UPDATE=false \
  --env SYFT_FILE_METADATA_SELECTION=none \
  --volume "$(abspath "$TAR"):/in/image.tar:ro" \
  "$SYFT_IMAGE" scan docker-archive:/in/image.tar \
  --output cyclonedx-json \
  --source-name "$NAME" \
  --source-version "$VERSION" \
  || die "syft failed"

count="$(jq '.components | length' "$OUT_FILE")"
log "wrote ${OUT_FILE} (${count} components)"
