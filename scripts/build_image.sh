#!/usr/bin/env bash
# Build the app image, tag it IMAGE_NAME:REV and save it as a tarball for the
# scanners. The local tag has no registry in it: build, scan and gate do not
# depend on where the image will be published.
# Env: IMAGE_NAME, REV (set by the Makefile), GIT_COMMIT (optional), OUT (default: build).
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

require_env IMAGE_NAME REV
require_cmd docker
OUT="${OUT:-build}"
mkdir -p "$OUT"
# A new build makes every earlier result stale.
for stale in image.tar trivy.json sbom.cdx.json trivy.sarif gate.json publish.json report.md; do
  rm -f "${OUT:?}/${stale}"
done

ref="${IMAGE_NAME}:${REV}"
log "building ${ref}"
docker build \
  --file app/Dockerfile \
  --tag "$ref" \
  --build-arg "REVISION=${REV}" \
  --label "org.opencontainers.image.title=devsecops-app" \
  --label "org.opencontainers.image.version=${REV}" \
  --label "org.opencontainers.image.revision=${GIT_COMMIT:-unknown}" \
  --label "org.opencontainers.image.source=$(source_url)" \
  --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --label "org.opencontainers.image.licenses=MIT" \
  app

# Scanners read this tarball instead of talking to the Docker daemon, so they
# never need /var/run/docker.sock (which is root on the host).
docker save --output "$OUT/image.tar" "$ref"
log "saved ${ref} to ${OUT}/image.tar ($(du -h "$OUT/image.tar" | cut -f1))"
