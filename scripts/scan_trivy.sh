#!/usr/bin/env bash
# Scan a saved image tarball with Trivy (vulnerabilities and secrets) and write
# the full JSON result. This script makes no pass/fail decision: gate.sh does.
# Results derived from an earlier scan (gate.json, trivy.sarif, publish.json,
# report.md next to the output) are removed first, so they cannot be mistaken
# for results of this scan.
# Usage: scan_trivy.sh <image.tar> <output.json>
# Env: TRIVY_CACHE_DIR (default .cache/trivy) holds the vulnerability DB between runs.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 2 ] || die "usage: $0 <image.tar> <output.json>"
TAR="$1"
OUT_FILE="$2"
CACHE_DIR="${TRIVY_CACHE_DIR:-.cache/trivy}"
require_cmd docker jq
[ -s "$TAR" ] || die "image tarball not found: ${TAR} (run 'make build' first)"
mkdir -p "$CACHE_DIR"

out_dir="$(dirname "$OUT_FILE")"
for stale in gate.json trivy.sarif publish.json report.md; do
  rm -f "${out_dir:?}/${stale}"
done

log "scanning ${TAR} with ${TRIVY_IMAGE%%@*}"
run_to_file "$OUT_FILE" docker run "${TOOL_RUN_FLAGS[@]}" \
  --env HOME=/tmp \
  --env TRIVY_DISABLE_TELEMETRY=true \
  --env TRIVY_SKIP_VERSION_CHECK=true \
  --volume "$(abspath "$TAR"):/in/image.tar:ro" \
  --volume "$(abspath "$CACHE_DIR"):/cache" \
  "$TRIVY_IMAGE" image \
  --input /in/image.tar \
  --cache-dir /cache \
  --scanners vuln,secret \
  --no-progress \
  --format json \
  || die "trivy scan failed"

count="$(jq '[.Results[]? | (.Vulnerabilities // [])[], (.Secrets // [])[]] | length' "$OUT_FILE")"
log "wrote ${OUT_FILE} (${count} findings, all severities)"
