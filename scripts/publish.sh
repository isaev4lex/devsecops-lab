#!/usr/bin/env bash
set -euo pipefail


#   ./scripts/publish.sh "<image:tag>"


require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "ERROR: $name is not set" >&2
    exit 1
  fi
}

require_env "ART_URL"
require_env "ART_USER"
require_env "ART_TOKEN"

if [ $# -ge 1 ]; then
  IMAGE_TAG="$1"
else
  echo "ERROR: image:tag argument is required" >&2
  exit 1
fi

REGISTRY="$(echo "${ART_URL}" | sed 's#https\?://##')"

echo "Logging in to ${REGISTRY} ..."
echo -n "${ART_TOKEN}" | docker login "${REGISTRY}" -u "${ART_USER}" --password-stdin

echo "Pushing ${IMAGE_TAG} ..."
docker push "${IMAGE_TAG}"

echo "Logout ..."
docker logout "${REGISTRY}" >/dev/null 2>&1 || true

echo "Publish done."
