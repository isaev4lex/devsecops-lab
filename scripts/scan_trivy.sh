#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <image:tag> <output.json>" >&2
  exit 1
fi

IMAGE="$1"
OUT="$2"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Scanning image: ${IMAGE}"
echo "Output file: ${OUT}"

check_critical() {
  local file="$1"
  if command -v jq >/dev/null 2>&1; then
    if jq -e '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")' "$file" >/dev/null 2>&1; then
      return 2
    fi
  else
    if grep -i "\"Severity\": *\"CRITICAL\"" -q "$file"; then
      return 2
    fi
  fi
  return 0
}

if command -v trivy >/dev/null 2>&1; then
  echo "Using local trivy CLI"
  trivy image --format json --output "$OUT" "$IMAGE" || true
else
  echo "Local trivy not found — using containerized trivy"
  docker pull aquasec/trivy:latest
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD":"$PWD" -w "$PWD" aquasec/trivy:latest image --format json --output "$OUT" "$IMAGE" || true
fi

echo "Scan finished. Checking CRITICAL vulnerabilities..."
if check_critical "$OUT"; then
  echo "No CRITICAL vulnerabilities found."
  exit 0
else
  echo "CRITICAL vulnerabilities detected! (exit code 2)"
  exit 2
fi
