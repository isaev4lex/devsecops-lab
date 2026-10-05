# shellcheck shell=bash
# Shared helpers and pinned tool images. Sourced by the other scripts, not run directly.

# Third-party tool images, pinned by version and digest (multi-arch index digest).
# A tag alone can be moved by whoever controls the repository; a digest cannot.
# Bump version and digest together, e.g.:
#   docker buildx imagetools inspect aquasec/trivy:<version>
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969}"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.52.0-nonroot@sha256:8b1c0cdeaa859b4553a1f499ef30f5173f5b4deb0f6e7ce5849632c7ac4b9c1b}"
REGISTRY_IMAGE="${REGISTRY_IMAGE:-registry:3.1.2@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8}"

# How tool containers run: as the calling user (not root), no Docker socket, no
# Linux capabilities, read-only root filesystem, no privilege escalation,
# scratch space in a tmpfs. Inputs are mounted read-only by each script and
# results come back on stdout. Running as the calling user also means the tools
# can read build outputs (docker save writes them mode 0600) without needing
# root's CAP_DAC_OVERRIDE, and files they write to the cache stay owned by you.
# shellcheck disable=SC2034 # used by the scripts that source this file
TOOL_RUN_FLAGS=(
  --rm
  --quiet
  --user "$(id -u):$(id -g)"
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --tmpfs /tmp
)

log() { printf '[%s] %s\n' "${0##*/}" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

require_env() {
  local name
  for name in "$@"; do
    [ -n "${!name:-}" ] || die "$name is not set"
  done
}

require_cmd() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
  done
}

# Absolute path of an existing file or directory (docker -v needs one).
abspath() {
  local dir
  dir="$(cd "$(dirname "$1")" && pwd -P)" || return 1
  printf '%s/%s\n' "$dir" "$(basename "$1")"
}

# run_to_file OUT CMD...: run CMD with stdout captured into OUT. OUT is removed
# first and only written when CMD succeeds with non-empty output, so a failed
# tool never leaves a stale or half-written result for a later stage to read.
run_to_file() {
  local out="$1" tmp
  shift
  rm -f "$out"
  mkdir -p "$(dirname "$out")"
  tmp="$(mktemp "${out}.XXXXXX")"
  if "$@" >"$tmp" && [ -s "$tmp" ]; then
    mv "$tmp" "$out"
  else
    rm -f "$tmp"
    return 1
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# curl against Artifactory. The token goes through a curl config on stdin so it
# never appears in the process list or in shell traces.
art_curl() {
  require_env ART_TOKEN
  printf 'header = "Authorization: Bearer %s"\n' "$ART_TOKEN" | curl --silent --show-error --fail --config - "$@"
}

# docker login without putting the token on the command line.
registry_login() {
  local host="$1"
  require_env ART_USER ART_TOKEN
  printf '%s' "$ART_TOKEN" | docker login "$host" --username "$ART_USER" --password-stdin >/dev/null
  log "logged in to registry"
}

registry_logout() {
  docker logout "$1" >/dev/null 2>&1 || true
}

# Config digest (sha256:...) of the image in a `docker save` tarball. This is
# the image ID that Trivy records as Metadata.ImageID, so the two can be compared.
tarball_config_digest() {
  local config
  config="$(tar -xOf "$1" manifest.json | jq -r '.[0].Config')" || return 1
  # "blobs/sha256/<hex>" (OCI layout, Docker 25+) or "<hex>.json" (older Docker).
  config="${config#blobs/sha256/}"
  config="${config%.json}"
  [[ $config =~ ^[0-9a-f]{64}$ ]] || return 1
  printf 'sha256:%s\n' "$config"
}

# Host part of ART_URL, e.g. https://example.jfrog.io/ -> example.jfrog.io
art_host() {
  local host="${ART_URL#http://}"
  host="${host#https://}"
  printf '%s\n' "${host%%/*}"
}

# Repository (without tag) that the image is pushed to for the current PUBLISH mode.
destination_repo() {
  local name="${IMAGE_NAME:-devsecops-app}"
  case "${PUBLISH:-local}" in
    local) printf 'localhost:%s/%s\n' "${LOCAL_REGISTRY_PORT:-5050}" "$name" ;;
    jfrog)
      require_env ART_URL
      printf '%s/%s/%s\n' "$(art_host)" "${ART_DOCKER_REPO:-docker-local}" "$name"
      ;;
    *) die "no registry for PUBLISH=${PUBLISH}" ;;
  esac
}
