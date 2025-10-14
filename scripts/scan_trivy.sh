#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <image:tag> <output.json>" >&2
  exit 1
fi

IMAGE="$1"
OUT="$2"

mkdir -p "$(dirname "$OUT")"

echo "Scanning image: ${IMAGE}"
echo "Output file: ${OUT}"

check_critical() {
  local file="$1"
  if command -v jq >/dev/null 2>&1; then
    if jq -e '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")' "$file" >/dev/null 2>&1; then
      return 2
    fi
  else
    if grep -qi '"Severity"\s*:\s*"CRITICAL"' "$file"; then
      return 2
    fi
  fi
  return 0
}

run_trivy_local() {
  trivy image --format json "$IMAGE" > "$OUT"
}

run_trivy_container() {
  echo "Local trivy not found — using containerized trivy"
  docker pull aquasec/trivy:latest >/dev/null
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy:latest \
    image --format json "$IMAGE" > "$OUT"
}

set +e
if command -v trivy >/dev/null 2>&1; then
  echo "Using local trivy CLI"
  run_trivy_local
  rc=$?
else
  run_trivy_container
  rc=$?
fi
set -e

if [ $rc -ne 0 ]; then
  echo "ERROR: trivy exited with code $rc" >&2
  if [ ! -s "$OUT" ]; then
    echo "ERROR: Trivy output missing or empty: $OUT" >&2
    exit $rc
  fi
fi

if [ ! -s "$OUT" ]; then
  echo "ERROR: Trivy output missing or empty: $OUT" >&2
  exit 1
fi

echo "Scan finished. Checking CRITICAL vulnerabilities..."
if check_critical "$OUT"; then
  echo "No CRITICAL vulnerabilities found."
  exit 0
else
  echo "CRITICAL vulnerabilities detected! (exit code 2)"
  exit 2
fi