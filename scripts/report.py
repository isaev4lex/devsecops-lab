#!/usr/bin/env python3
"""Write a Markdown security report from the pipeline outputs.

Reads (from --dir, default build/):
  trivy.json      scan result (required for the vulnerability section)
  gate.json       gate decision written by gate.sh
  sbom.cdx.json   CycloneDX SBOM
  publish.json    where the image was pushed (absent when not published)

Missing inputs are reported as missing rather than treated as an error, so a
report can still be written after a failed stage. The report restates the gate
decision from gate.json; it never re-evaluates the policy.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
MAX_ROWS = 30


def load(path):
    try:
        with path.open() as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def scanned_at(trivy):
    created = trivy.get("CreatedAt") or ""
    return created[:19] + "Z" if len(created) >= 19 else "unknown time"


def image_section(trivy, publish):
    lines = ["| Item | Value |", "|---|---|"]
    if trivy:
        meta = trivy.get("Metadata", {})
        config = meta.get("ImageConfig", {})
        labels = config.get("config", {}).get("Labels") or {}
        os_info = meta.get("OS") or {}
        lines += [
            "| Image | `%s:%s` |" % (labels.get("org.opencontainers.image.title", "?"),
                                  labels.get("org.opencontainers.image.version", "?")),
            "| Commit | `%s` |" % labels.get("org.opencontainers.image.revision", "unknown"),
            "| Image ID | `%s` |" % meta.get("ImageID", "unknown"),
            "| Base OS | %s %s |" % (os_info.get("Family", "?"), os_info.get("Name", "?")),
            "| Platform | %s/%s |" % (config.get("os", "?"), config.get("architecture", "?")),
            "| User | `%s` |" % (config.get("config", {}).get("User") or "root"),
            "| Scanned | %s with Trivy %s |" % (scanned_at(trivy), (trivy.get("Trivy") or {}).get("Version", "?")),
        ]
    published = publish and publish.get("target") in ("local", "jfrog")
    # Ignore a publish.json left over from a different image.
    if published and trivy and publish.get("config_digest") != trivy.get("Metadata", {}).get("ImageID"):
        published = False
    if published:
        where = "local registry %s" % publish.get("registry") if publish["target"] == "local" else "JFrog Artifactory"
        lines.append("| Published | `%s@%s` (%s) |" % (publish["repository"], publish["digest"], where))
    else:
        lines.append("| Published | no |")
    return lines


def gate_section(gate):
    if gate is None:
        return ["## Gate: not run", "", "`gate.json` not found."]
    policy = gate["policy"]
    lines = [
        "## Gate: %s" % gate["decision"].upper(),
        "",
        "Policy: fail on any %s or above finding; fail on %s or above when a fixed version exists; "
        "any secret fails." % (policy["fail_on_severity"], policy["fail_on_fixable_severity"]),
        "Waivers: %s, %d finding(s) waived, %d expired entr%s."
        % ("`%s`" % policy["ignore_file"] if policy["ignore_file"] else "none",
           len(gate["waived"]), len(gate["expired_waivers"]),
           "y" if len(gate["expired_waivers"]) == 1 else "ies"),
        "",
    ]
    if gate["blocking"]:
        lines += ["Blocking findings:", "", "| Severity | ID | Package | Installed | Fixed | Reason |",
                  "|---|---|---|---|---|---|"]
        for f in gate["blocking"][:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                f["severity"], f["id"], f["package"] or f["target"], f["installed"],
                f["fixed"] or "-", f["reason"]))
        if len(gate["blocking"]) > MAX_ROWS:
            lines.append("| ... | %d more in gate.json | | | | |" % (len(gate["blocking"]) - MAX_ROWS))
    else:
        lines.append("Blocking findings: none.")
    for w in gate["waived"]:
        lines.append("- Waived until %s: %s in %s" % (w["waived_until"], w["id"], w["package"] or w["target"]))
    for w in gate["expired_waivers"]:
        lines.append("- Expired waiver (no longer applied): %s, expired %s" % (w["id"], w["expires"]))
    return lines


def vulnerability_section(trivy):
    if trivy is None:
        return ["## Vulnerabilities", "", "`trivy.json` not found."]
    vulns, secrets = [], 0
    for result in trivy.get("Results") or []:
        vulns += result.get("Vulnerabilities") or []
        secrets += len(result.get("Secrets") or [])
    total = Counter(v.get("Severity", "UNKNOWN") for v in vulns)
    fixable = Counter(v.get("Severity", "UNKNOWN") for v in vulns if v.get("FixedVersion"))
    lines = ["## Vulnerabilities", "", "| Severity | Total | Fix available |", "|---|---:|---:|"]
    lines += ["| %s | %d | %d |" % (s, total[s], fixable[s]) for s in SEVERITIES]
    lines += ["", "Secrets found: %d." % secrets]

    serious = sorted(
        (v for v in vulns if v.get("Severity") in ("CRITICAL", "HIGH")),
        key=lambda v: (SEVERITIES.index(v["Severity"]), v.get("PkgName", ""), v["VulnerabilityID"]),
    )
    if serious:
        lines += ["", "HIGH and CRITICAL findings:", "",
                  "| Severity | ID | Package | Installed | Fixed | Status |", "|---|---|---|---|---|---|"]
        for v in serious[:MAX_ROWS]:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                v["Severity"], v["VulnerabilityID"], v.get("PkgName", ""), v.get("InstalledVersion", ""),
                v.get("FixedVersion") or "-", v.get("Status", "")))
        if len(serious) > MAX_ROWS:
            lines.append("| ... | %d more in trivy.json | | | | |" % (len(serious) - MAX_ROWS))
    return lines


def sbom_section(sbom):
    if sbom is None:
        return ["## SBOM", "", "`sbom.cdx.json` not found."]
    components = sbom.get("components") or []
    by_type = Counter(c.get("type", "unknown") for c in components)
    tools = (sbom.get("metadata", {}).get("tools") or {}).get("components") or []
    generator = ", ".join("%s %s" % (t.get("name"), t.get("version")) for t in tools) or "unknown"
    return [
        "## SBOM",
        "",
        "- Format: %s %s (JSON), generated by %s" % (sbom.get("bomFormat"), sbom.get("specVersion"), generator),
        "- Components: %d (%s)" % (len(components), ", ".join("%s: %d" % kv for kv in sorted(by_type.items()))),
        "- File: `sbom.cdx.json`",
    ]


def render(directory):
    trivy = load(directory / "trivy.json")
    gate = load(directory / "gate.json")
    sbom = load(directory / "sbom.cdx.json")
    publish = load(directory / "publish.json")
    sections = [
        ["# Security report"],
        image_section(trivy, publish),
        gate_section(gate),
        vulnerability_section(trivy),
        sbom_section(sbom),
    ]
    return "\n\n".join("\n".join(s) for s in sections) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=Path("build"), help="pipeline output directory")
    parser.add_argument("--out", type=Path, help="write here instead of stdout")
    args = parser.parse_args(argv)
    text = render(args.dir)
    if args.out:
        args.out.write_text(text)
        print("wrote %s" % args.out, file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
