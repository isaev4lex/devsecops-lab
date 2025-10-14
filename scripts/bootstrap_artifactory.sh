#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "ERROR: $name is not set" >&2
    exit 1
  fi
}

require_env "ART_URL"
require_env "ART_TOKEN"

api() {
  local method="$1"; shift
  local path="$1"; shift
  curl -sS -f -X "$method" \
    -H "Authorization: Bearer ${ART_TOKEN}" \
    -H "Content-Type: application/json" \
    "${ART_URL}/artifactory${path}" "$@"
}

ensure_repo() {
  local key="$1"
  local payload="$2"

  echo ">> Ensuring repo '${key}' ..."
  if api GET "/api/repositories/${key}" >/dev/null 2>&1; then
    echo "   - Exists. Updating (idempotent PUT) ..."
  else
    echo "   - Not found. Creating ..."
  fi

  api PUT "/api/repositories/${key}" --data "${payload}" >/dev/null
  echo "   - OK"
}

docker_local_payload='{
  "key": "docker-local",
  "rclass": "local",
  "packageType": "Docker",
  "dockerApiVersion": "V2"
}'

generic_local_payload='{
  "key": "generic-local",
  "rclass": "local",
  "packageType": "Generic"
}'

ensure_repo "docker-local"  "${docker_local_payload}"
ensure_repo "generic-local" "${generic_local_payload}"

echo "All good. Repositories are ready."