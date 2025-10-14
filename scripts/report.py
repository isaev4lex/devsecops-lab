#!/usr/bin/env python3
import json
import sys
from pathlib import Path


TRIVY_FILE = Path("trivy.json")
SBOM_FILE = Path("sbom/sbom.cdx.json")


def main():
    print("# DevSecOps Security Report\n")

    print("## 1. Vulnerability Scan (Trivy)\n")
    if TRIVY_FILE.exists():
        with TRIVY_FILE.open() as f:
            data = json.load(f)
        total_vulns = 0
        high = 0
        critical = 0
        for r in data.get("Results", []):
            vulns = r.get("Vulnerabilities", []) or []
            total_vulns += len(vulns)
            for v in vulns:
                sev = v.get("Severity", "").upper()
                if sev == "HIGH":
                    high += 1
                elif sev == "CRITICAL":
                    critical += 1
        print(f"- Total vulnerabilities: {total_vulns}")
        print(f"- HIGH: {high}")
        print(f"- CRITICAL: {critical}\n")
    else:
        print("- trivy.json not found\n")

    print("## 2. SBOM (CycloneDX)\n")
    if SBOM_FILE.exists():
        with SBOM_FILE.open() as f:
            sbom_data = json.load(f)
        comps = sbom_data.get("components", [])
        print(f"- Total components in SBOM: {len(comps)}\n")
    else:
        print("- sbom/sbom.cdx.json not found\n")


if __name__ == "__main__":
    main()
