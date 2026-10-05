# Container supply-chain pipeline: build -> smoke -> scan -> sbom -> sarif -> gate -> publish -> report.
# `make help` lists the targets. Works with GNU Make 3.81 (the macOS default) and newer.

# Optional local settings and JFrog credentials (see .env.example). No quotes around values.
-include .env
export

IMAGE_NAME          ?= devsecops-app
OUT                 ?= build
TRIVYIGNORE         ?= .trivyignore
LOCAL_REGISTRY_PORT ?= 5050
ART_DOCKER_REPO     ?= docker-local
ART_GENERIC_REPO    ?= generic-local
PYTHON              ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
# Workflow linter, pinned by version and digest like the tool images in scripts/lib.sh.
ACTIONLINT_IMAGE    ?= rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

# Image tag: the short git commit, plus "-dirty" when tracked files have
# uncommitted changes. Outside a git checkout (e.g. a downloaded archive) it is
# "src-" plus a hash of the build inputs, so separate make runs on the same
# sources agree on it and stages can be run one at a time.
# Computed once and exported, so the recursive make calls in `ci` reuse it.
ifeq ($(origin REV),undefined)
  GIT_SHORT := $(shell git rev-parse --short=12 HEAD 2>/dev/null)
  ifneq ($(GIT_SHORT),)
    REV := $(GIT_SHORT)$(shell git diff --quiet HEAD -- 2>/dev/null || echo -dirty)
  else
    SHA256_CMD := $(if $(shell command -v sha256sum 2>/dev/null),sha256sum,shasum -a 256)
    REV := src-$(shell cat app/Dockerfile app/main.py | $(SHA256_CMD) | cut -c1-12)
  endif
endif
GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)

# Where `publish` pushes: jfrog when ART_URL, ART_USER and ART_TOKEN are all
# set, otherwise a throwaway local registry. Override with PUBLISH=local|jfrog|none.
ifeq ($(origin PUBLISH),undefined)
  ifneq ($(and $(ART_URL),$(ART_USER),$(ART_TOKEN)),)
    PUBLISH := jfrog
  else
    PUBLISH := local
  endif
endif
ifeq ($(filter $(PUBLISH),local jfrog none),)
  $(error PUBLISH must be local, jfrog or none, got "$(PUBLISH)")
endif

.DEFAULT_GOAL := help
.PHONY: help ci build smoke scan sbom sarif gate publish report upload sign bootstrap \
        lint lint-workflows test check clean registry-down

help: ## Show this help
	@echo "Targets (REV=$(REV), PUBLISH=$(PUBLISH)):"
	@awk 'BEGIN { FS = ":.*## " } /^[a-z-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

ci: ## Whole pipeline. The report is written even when the gate fails.
	@$(MAKE) --no-print-directory build smoke scan sbom sarif
	@rc=0; \
	$(MAKE) --no-print-directory gate || rc=$$?; \
	if [ $$rc -eq 0 ]; then $(MAKE) --no-print-directory publish || rc=$$?; fi; \
	$(MAKE) --no-print-directory report || [ $$rc -ne 0 ] || rc=1; \
	if [ $$rc -eq 0 ] && [ "$(PUBLISH)" = jfrog ]; then $(MAKE) --no-print-directory upload || rc=$$?; fi; \
	exit $$rc

build: ## Build the image as IMAGE_NAME:REV and save it to build/image.tar
	@bash scripts/build_image.sh

smoke: ## Run the image read-only and non-root; check HEALTHCHECK, /health and /version
	@bash scripts/smoke_test.sh "$(IMAGE_NAME):$(REV)" "$(REV)"

scan: ## Trivy scan of the tarball -> build/trivy.json (no pass/fail here)
	@bash scripts/scan_trivy.sh $(OUT)/image.tar $(OUT)/trivy.json

sbom: ## Syft CycloneDX SBOM of the tarball -> build/sbom.cdx.json
	@bash scripts/generate_sbom.sh $(OUT)/image.tar $(OUT)/sbom.cdx.json "$(IMAGE_NAME)" "$(REV)"

sarif: ## Convert the scan to SARIF for GitHub code scanning -> build/trivy.sarif
	@bash scripts/to_sarif.sh $(OUT)/trivy.json $(OUT)/trivy.sarif

gate: ## Apply the vulnerability policy to build/trivy.json -> build/gate.json
	@bash scripts/gate.sh $(OUT)/trivy.json $(TRIVYIGNORE)

publish: ## Push the gated image (PUBLISH=local|jfrog|none) -> build/publish.json
	@bash scripts/publish.sh

report: ## Markdown summary of scan, gate, SBOM and publish -> build/report.md
	@$(PYTHON) scripts/report.py --dir $(OUT) --out $(OUT)/report.md

upload: ## Upload scan, SBOM, SARIF, gate result and report to the JFrog generic repo
	@bash scripts/upload_artifacts.sh "$(REV)" $(OUT)/trivy.json $(OUT)/sbom.cdx.json \
		$(OUT)/trivy.sarif $(OUT)/gate.json $(OUT)/report.md

sign: ## Keyless cosign signature + SBOM attestation (GitHub Actions only, needs DIGEST)
	@bash scripts/sign_image.sh

bootstrap: ## Create the JFrog docker and generic repositories if missing
	@bash scripts/bootstrap_artifactory.sh

lint: ## shellcheck all scripts
	shellcheck -x scripts/*.sh

lint-workflows: ## actionlint on .github/workflows (Docker, pinned image, no network)
	docker run --rm --quiet --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --user "$$(id -u):$$(id -g)" \
		--volume "$(CURDIR):/repo:ro" --workdir /repo $(ACTIONLINT_IMAGE) -color=false

test: ## pytest (app endpoints, gate policy, report)
	$(PYTHON) -m pytest

check: lint test ## lint + test

clean: ## Remove pipeline outputs
	rm -rf $(OUT)

registry-down: ## Stop and remove the throwaway local registry
	-docker rm --force devsecops-lab-registry
