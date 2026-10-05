#!/usr/bin/env bash
# Keyless signing with cosign, for images pushed to JFrog from GitHub Actions.
# The signing certificate is issued by Sigstore for the workflow's OIDC
# identity, so no key is stored anywhere. Also attaches the CycloneDX SBOM as a
# signed attestation, then verifies both against the expected workflow identity.
#
# Runs only in GitHub Actions with `permissions: id-token: write`. Signing writes
# an entry to the public Rekor transparency log.
# Env: DIGEST (sha256:... of the pushed image), ART_URL, ART_USER, ART_TOKEN.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

require_env DIGEST ART_URL ART_USER ART_TOKEN
require_cmd cosign docker
[[ $DIGEST =~ ^sha256:[0-9a-f]{64}$ ]] || die "DIGEST must be sha256:<64 hex>, got '${DIGEST}'"
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] \
  || die "keyless signing needs a GitHub Actions OIDC token (permissions: id-token: write)"
SBOM="${OUT:-build}/sbom.cdx.json"
[ -s "$SBOM" ] || die "SBOM not found: ${SBOM}"

PUBLISH=jfrog
ref="$(destination_repo)@${DIGEST}"
host="$(art_host)"
registry_login "$host"
trap 'registry_logout "$host"' EXIT

identity="${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}"
issuer="https://token.actions.githubusercontent.com"

cosign sign --yes "$ref"
cosign attest --yes --type cyclonedx --predicate "$SBOM" "$ref"

cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$ref" >/dev/null
cosign verify-attestation --type cyclonedx \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$ref" >/dev/null
log "signed and verified ${DIGEST} (identity ${identity})"
