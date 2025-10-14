#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <image:tag> <output.cdx.json>" >&2
  exit 1
fi

IMAGE="$1"
OUT="$2"
mkdir -p "$(dirname "$OUT")"

echo "Generating SBOM (CycloneDX JSON) for ${IMAGE} -> ${OUT}"

if command -v syft >/dev/null 2>&1; then
  echo "Using local syft CLI"
  syft "${IMAGE}" -o cyclonedx-json > "${OUT}"
else
  echo "Local syft not found — using containerized syft"
  docker pull anchore/syft:latest
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    anchore/syft:latest \
    "${IMAGE}" -o cyclonedx-json > "${OUT}"
fi

echo "SBOM written to ${OUT}"