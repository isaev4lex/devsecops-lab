#!/usr/bin/env bash
# Create the two Artifactory repositories the pipeline uses, if missing:
#   $ART_DOCKER_REPO  (default docker-local)   local Docker repository for images
#   $ART_GENERIC_REPO (default generic-local)  local generic repository for reports
# Safe to run repeatedly: an existing repository is left as it is.
# (In the Artifactory REST API, PUT creates a repository and fails if it exists.)
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

require_env ART_URL ART_TOKEN
require_cmd curl
api="${ART_URL%/}/artifactory/api/repositories"

ensure_repo() {
  local key="$1" payload="$2"
  if art_curl --output /dev/null "${api}/${key}" 2>/dev/null; then
    log "repository ${key} exists, leaving it unchanged"
    return
  fi
  art_curl --request PUT --header "Content-Type: application/json" \
    --data "$payload" --output /dev/null "${api}/${key}" || die "could not create ${key}"
  log "created repository ${key}"
}

docker_repo="${ART_DOCKER_REPO:-docker-local}"
generic_repo="${ART_GENERIC_REPO:-generic-local}"
ensure_repo "$docker_repo" \
  "{\"key\": \"${docker_repo}\", \"rclass\": \"local\", \"packageType\": \"docker\", \"dockerApiVersion\": \"V2\"}"
ensure_repo "$generic_repo" \
  "{\"key\": \"${generic_repo}\", \"rclass\": \"local\", \"packageType\": \"generic\"}"
log "repositories ready"
