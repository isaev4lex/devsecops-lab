#!/usr/bin/env bash
# Convert the Trivy JSON result to SARIF for GitHub code scanning. No second
# scan: this reads the same JSON that the gate evaluates.
# Every result is attached to the FROM line of the Dockerfile, because that is
# the line to change (base image digest) to pick up fixed packages. Since all
# results share that line, each gets its own fingerprint (rule ID plus Trivy's
# "<target>: <package>@<version>" location text). Without one, upload-sarif
# derives it from the text of the line, the same for every result, and code
# scanning could merge one CVE found in several packages into one alert.
# Usage: to_sarif.sh <trivy.json> <output.sarif>
# Env: SARIF_SEVERITY (default MEDIUM,HIGH,CRITICAL) limits what becomes an alert.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -eq 2 ] || die "usage: $0 <trivy.json> <output.sarif>"
IN="$1"
OUT_FILE="$2"
SEVERITY="${SARIF_SEVERITY:-MEDIUM,HIGH,CRITICAL}"
DOCKERFILE="${DOCKERFILE:-app/Dockerfile}"
require_cmd docker jq
[ -s "$IN" ] || die "scan result not found: ${IN} (run 'make scan' first)"

from_line="$(awk '/^FROM /{print NR; exit}' "$DOCKERFILE")"
[ -n "$from_line" ] || die "no FROM line in ${DOCKERFILE}"

raw="$(mktemp)"
trap 'rm -f "$raw"' EXIT

docker run "${TOOL_RUN_FLAGS[@]}" \
  --env HOME=/tmp \
  --env TRIVY_DISABLE_TELEMETRY=true \
  --env TRIVY_SKIP_VERSION_CHECK=true \
  --volume "$(abspath "$IN"):/in/trivy.json:ro" \
  "$TRIVY_IMAGE" convert --format sarif --severity "$SEVERITY" /in/trivy.json >"$raw" \
  || die "trivy convert failed"

# shellcheck disable=SC2016 # $uri and $line are jq variables
run_to_file "$OUT_FILE" jq --arg uri "$DOCKERFILE" --argjson line "$from_line" '
  (.runs[].results[] |= (.partialFingerprints.primaryLocationLineHash =
    "\(.ruleId)|\(.locations[0].message.text // .message.text)"))
  | (.runs[].results[] | select(.locations != null) | .locations[].physicalLocation) |= {
    artifactLocation: {uri: $uri},
    region: {startLine: $line, startColumn: 1, endLine: $line, endColumn: 1}
  }' "$raw" \
  || die "could not rewrite SARIF locations"

count="$(jq '[.runs[].results[]] | length' "$OUT_FILE")"
distinct="$(jq '[.runs[].results[].partialFingerprints.primaryLocationLineHash] | unique | length' "$OUT_FILE")"
[ "$distinct" = "$count" ] || log "WARN: ${count} results but only ${distinct} distinct fingerprints"
log "wrote ${OUT_FILE} (${count} results at ${SEVERITY}, located at ${DOCKERFILE}:${from_line})"
