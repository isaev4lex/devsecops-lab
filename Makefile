ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: bootstrap build scan sbom gate push publish report ci
REGISTRY := $(shell echo $(ART_URL) | sed 's#https\?://##')
IMAGE_NAME := devsecops-app
IMG := $(REGISTRY)/docker-local/$(IMAGE_NAME)
REV := $(shell git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)
ifneq (,$(wildcard .rev))
REV := $(shell cat .rev)
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
