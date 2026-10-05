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

# Source URL for the OCI label, normalised to https and stripped of any
# credentials that may be embedded in the remote URL.
source_url() {
  local url
  if [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
    printf '%s/%s\n' "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY"
    return
  fi
  url="$(git config --get remote.origin.url 2>/dev/null || true)"
  [ -n "$url" ] || { echo unknown; return; }
  if [[ $url =~ ^git@([^:]+):(.+)$ ]]; then
    url="https://${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
  fi
  if [[ $url =~ ^(https?://)[^/@]*@(.*)$ ]]; then
    url="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
  fi
  printf '%s\n' "${url%.git}"
}

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
