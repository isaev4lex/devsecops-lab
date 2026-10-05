#!/usr/bin/env bash
# Push the image that was scanned and passed the gate.
#
# PUBLISH selects the destination:
#   local  a throwaway registry container on 127.0.0.1:$LOCAL_REGISTRY_PORT (default 5050)
#   jfrog  $ART_URL, repository $ART_DOCKER_REPO; needs ART_URL, ART_USER, ART_TOKEN
#   none   skip publishing
#
# Before pushing it checks that build/gate.json says "pass", that the gate
# evaluated the current build/trivy.json (gate.json records its SHA-256), and
# that the image in build/image.tar is the one Trivy scanned (same config
# digest). It then loads that tarball and pushes it, so the bytes pushed are the
# bytes scanned, and reads the manifest back from the registry to check the
# config digest again.
# Writes build/publish.json with the pushed digest.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

require_env IMAGE_NAME REV
require_cmd docker jq curl
OUT="${OUT:-build}"
PUBLISH="${PUBLISH:-local}"
REGISTRY_CONTAINER="devsecops-lab-registry"
rm -f "$OUT/publish.json"

if [ "$PUBLISH" = "none" ]; then
  log "PUBLISH=none: not publishing"
  jq -n '{target: "none"}' >"$OUT/publish.json"
  exit 0
fi

# 1. Only gated images leave the machine.
[ -s "$OUT/gate.json" ] || die "no gate result at ${OUT}/gate.json (run 'make gate' first)"
decision="$(jq -r '.decision' "$OUT/gate.json")"
[ "$decision" = "pass" ] || die "refusing to publish: gate decision is '${decision}'"

# 2. The decision must be about the current scan, not an earlier one.
[ -s "$OUT/trivy.json" ] || die "no scan result at ${OUT}/trivy.json (run 'make scan gate' first)"
gated_sha="$(jq -r '.input_sha256 // empty' "$OUT/gate.json")"
[ "$gated_sha" = "$(sha256_of "$OUT/trivy.json")" ] \
  || die "refusing to publish: ${OUT}/gate.json was not computed from the current ${OUT}/trivy.json; run 'make gate' again"

# 3. The tarball must be the image that was scanned.
scanned="$(jq -r '.Metadata.ImageID // empty' "$OUT/trivy.json")"
built="$(tarball_config_digest "$OUT/image.tar")" || die "cannot read image config digest from ${OUT}/image.tar"
[ "$scanned" = "$built" ] \
  || die "image.tar (${built}) is not the scanned image (${scanned}); run 'make scan gate' again"

# 4. Load exactly those bytes and tag them for the destination.
src="${IMAGE_NAME}:${REV}"
docker load --quiet --input "$OUT/image.tar" >/dev/null
dest_repo="$(destination_repo)"
dest="${dest_repo}:${REV}"
docker tag "$src" "$dest"

start_local_registry() {
  local port="${LOCAL_REGISTRY_PORT:-5050}"
  if [ "$(docker container inspect --format '{{.State.Running}}' "$REGISTRY_CONTAINER" 2>/dev/null || true)" != "true" ]; then
    docker rm --force "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
    log "starting throwaway registry ${REGISTRY_IMAGE%%@*} on 127.0.0.1:${port}"
    # Storage is a tmpfs: everything pushed disappears with the container.
    docker run --detach --quiet --name "$REGISTRY_CONTAINER" \
      --read-only \
      --tmpfs /var/lib/registry \
      --tmpfs /tmp \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --publish "127.0.0.1:${port}:5000" \
      "$REGISTRY_IMAGE" >/dev/null
  fi
  for _ in $(seq 20); do
    curl --silent --fail --output /dev/null "http://127.0.0.1:${port}/v2/" && return 0
    sleep 0.5
  done
  docker logs "$REGISTRY_CONTAINER" >&2 || true
  die "local registry did not become ready on 127.0.0.1:${port}"
}

# Push and print the pushed digest, taken from the "digest: sha256:..." line of
# docker push. The full push log is shown only when something goes wrong.
push_and_get_digest() {
  local output rc=0 digest_re='digest: (sha256:[0-9a-f]{64})'
  output="$(docker push "$1" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ] || ! [[ $output =~ $digest_re ]]; then
    printf '%s\n' "$output" >&2
    return 1
  fi
  printf '%s\n' "${BASH_REMATCH[1]}"
}

# Read the manifest back from the registry and check that its config digest is
# the scanned image ID. Handles both a single manifest and an index.
verify_pushed() {
  local ref="$1" manifest child config
  if ! docker buildx version >/dev/null 2>&1; then
    log "WARN: docker buildx not available, skipping the read-back check"
    return 0
  fi
  manifest="$(docker buildx imagetools inspect --raw "$ref")" || die "cannot read back ${ref##*/}"
  child="$(jq -r '[.manifests[]? | select(.platform.os != "unknown")][0].digest // empty' <<<"$manifest")"
  if [ -n "$child" ]; then
    manifest="$(docker buildx imagetools inspect --raw "${ref%@*}@${child}")" || die "cannot read back ${child}"
  fi
  config="$(jq -r '.config.digest' <<<"$manifest")"
  [ "$config" = "$scanned" ] || die "registry has config ${config}, expected the scanned image ${scanned}"
  log "verified: ${ref##*/} in the registry has the scanned config ${scanned}"
}

case "$PUBLISH" in
  local)
    start_local_registry
    digest="$(push_and_get_digest "$dest")" || die "push to local registry failed"
    verify_pushed "${dest_repo}@${digest}"
    jq -n --arg registry "localhost:${LOCAL_REGISTRY_PORT:-5050}" --arg repo "$IMAGE_NAME" \
      --arg tag "$REV" --arg digest "$digest" --arg config "$scanned" \
      '{target: "local", registry: $registry, repository: $repo, tag: $tag, digest: $digest, config_digest: $config}' \
      >"$OUT/publish.json"
    ;;
  jfrog)
    host="$(art_host)"
    registry_login "$host"
    trap 'registry_logout "$host"' EXIT
    digest="$(push_and_get_digest "$dest")" || die "push to JFrog failed"
    verify_pushed "${dest_repo}@${digest}"
    # The registry host is left out on purpose: publish.json and the report are
    # uploaded as CI artifacts, and the instance URL is kept in a secret.
    jq -n --arg repo "${ART_DOCKER_REPO:-docker-local}/${IMAGE_NAME}" \
      --arg tag "$REV" --arg digest "$digest" --arg config "$scanned" \
      '{target: "jfrog", repository: $repo, tag: $tag, digest: $digest, config_digest: $config}' \
      >"$OUT/publish.json"
    ;;
  *) die "PUBLISH must be local, jfrog or none (got '${PUBLISH}')" ;;
esac

log "published ${dest_repo##*/}@${digest} (${PUBLISH})"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "digest=${digest}" >>"$GITHUB_OUTPUT"
fi
