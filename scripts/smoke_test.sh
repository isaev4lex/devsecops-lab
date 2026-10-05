#!/usr/bin/env bash
# Run the image the way it should run in production (read-only root filesystem,
# no capabilities, no privilege escalation) and check that:
#   - it does not run as root,
#   - the Docker HEALTHCHECK reports healthy,
#   - GET /health returns {"status": "ok"} and /version returns the built revision.
# Usage: smoke_test.sh <image:tag> [expected-revision]
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

[ $# -ge 1 ] || die "usage: $0 <image:tag> [expected-revision]"
IMAGE="$1"
EXPECTED_REV="${2:-}"
TIMEOUT_SECONDS="${SMOKE_TIMEOUT_SECONDS:-30}"
require_cmd docker curl jq

user="$(docker image inspect --format '{{.Config.User}}' "$IMAGE")"
case "${user%%:*}" in
  "" | root | 0) die "image runs as root (Config.User='${user}')" ;;
esac
log "image user: ${user}"

name="devsecops-smoke-$$"
cleanup() { docker rm --force "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run --detach --name "$name" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --publish 127.0.0.1::3000 \
  --health-interval 1s \
  "$IMAGE" >/dev/null

status=""
for _ in $(seq "$TIMEOUT_SECONDS"); do
  status="$(docker inspect --format '{{.State.Status}} {{.State.Health.Status}}' "$name")"
  case "$status" in
    "running healthy") break ;;
    exited* | dead*) docker logs "$name" >&2 || true; die "container stopped: ${status}" ;;
  esac
  sleep 1
done
if [ "$status" != "running healthy" ]; then
  docker logs "$name" >&2 || true
  die "container not healthy after ${TIMEOUT_SECONDS}s (state: ${status})"
fi
log "HEALTHCHECK: healthy"

addr="$(docker port "$name" 3000/tcp | head -n 1)"
health="$(curl --silent --show-error --fail --max-time 5 "http://${addr}/health")"
jq -e '.status == "ok"' >/dev/null <<<"$health" || die "unexpected /health body: ${health}"
log "GET /health: ${health}"

version="$(curl --silent --show-error --fail --max-time 5 "http://${addr}/version")"
if [ -n "$EXPECTED_REV" ]; then
  jq -e --arg rev "$EXPECTED_REV" '.revision == $rev' >/dev/null <<<"$version" \
    || die "unexpected /version body: ${version} (expected revision ${EXPECTED_REV})"
fi
log "GET /version: ${version}"
log "smoke test passed"
