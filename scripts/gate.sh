#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <trivy.json> <policy-name>" >&2
  exit 1
fi

IN="$1"
POLICY="$2" 

echo "Gate policy: ${POLICY}"
echo "Reading: ${IN}"

if [ ! -s "$IN" ]; then
  echo "ERROR: input file not found or empty: $IN" >&2
  exit 1
fi

fail=0

if command -v jq >/dev/null 2>&1; then
  highs=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="HIGH")] | length' "$IN")
  crits=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' "$IN")
else
  # rough fallback
  highs=$(grep -oi '"Severity": *"HIGH"' "$IN" | wc -l | tr -d ' ')
  crits=$(grep -oi '"Severity": *"CRITICAL"' "$IN" | wc -l | tr -d ' ')
fi

echo "Found HIGH: ${highs}, CRITICAL: ${crits}"

if [ "${crits}" != "0" ] || [ "${highs}" != "0" ]; then
  echo "Gate FAILED: HIGH/CRITICAL vulnerabilities present."
  exit 2
fi

echo "Gate PASSED: no HIGH/CRITICAL vulnerabilities."
