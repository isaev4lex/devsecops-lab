# DevSecOps Lab (Free Stack)

Minimal pipeline: **build → scan (Trivy) → SBOM (Syft) → gate → publish (Docker) → upload artifacts (Generic) → report**.

## Prerequisites
- Docker (with access to the local daemon)
- A JFrog Cloud instance
- Access token with permissions to:
  - create local repositories
  - push Docker images
  - upload generic artifacts

## Quick Start
1. Copy environment template:
```
cp .env.example .env
```

2. Fill in `.env`:
```
ART_URL=...
ART_USER=...
ART_TOKEN=...
```

3. Ensure repositories exist:
```
make bootstrap
```

4. Run the full pipeline:
```
make ci
```

## One-liner CI
```
make ci
```

## Outputs
- Docker image:
```
<subdomain>.jfrog.io/docker-local/devsecops-app:<rev>
```

- Artifacts in JFrog:
```
generic-local/devsecops-app/<rev>/
  ├─ trivy.json
  ├─ sbom.cdx.json
  └─ report.md
```

## Pipeline (ASCII)
```
[build] -> [scan:trivy] -> [sbom:syft] -> [gate]
    \--------------------------------------------> [publish:docker-local]
                                                  -> [report.md]
                                                  -> [upload:generic-local]
```

## Notes
- The build revision is stored in `.rev`, so subsequent steps reuse the same tag.
- `make gate` fails on HIGH/CRITICAL vulnerabilities (exit code 2).
- All scripts are idempotent where possible.
# Trigger CI
