ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: bootstrap build scan sbom gate push publish report ci
REGISTRY := $(shell echo $(ART_URL) | sed 's#https\?://##')
IMAGE_NAME := devsecops-app
IMG := $(REGISTRY)/docker-local/$(IMAGE_NAME)
# Image tag: the short git commit, plus "-dirty" when tracked files have
# uncommitted changes. Outside a git checkout it falls back to a UTC timestamp.
ifeq ($(origin REV),undefined)
  GIT_SHORT := $(shell git rev-parse --short=12 HEAD 2>/dev/null)
  ifneq ($(GIT_SHORT),)
    REV := $(GIT_SHORT)$(shell git diff --quiet HEAD -- 2>/dev/null || echo -dirty)
  else
    REV := $(shell date -u +%Y%m%d%H%M%S)
  endif
endif
export REV

export ART_URL ART_USER ART_TOKEN REGISTRY IMAGE_NAME IMG REV

bootstrap:
	@bash scripts/bootstrap_artifactory.sh

build:
	@bash scripts/build_image.sh

scan:
	@bash scripts/scan_trivy.sh "$(IMG):$(REV)" trivy.json

sbom:
	@bash scripts/generate_sbom.sh "$(IMG):$(REV)" sbom/sbom.cdx.json

gate:
	@bash scripts/gate.sh trivy.json policy

push:
	@bash scripts/publish.sh "$(IMG):$(REV)"

artifacts:
	@bash scripts/upload_artifacts.sh "$(REV)" trivy.json sbom/sbom.cdx.json reports/report.md


publish: push

report:
	@mkdir -p reports
	@python3 scripts/report.py > reports/report.md

ci: build scan sbom gate publish report artifacts
