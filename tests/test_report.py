import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("report", ROOT / "scripts" / "report.py")
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)

TRIVY = {
    "SchemaVersion": 2,
    "CreatedAt": "2026-06-01T10:00:00.123Z",
    "Trivy": {"Version": "0.74.0"},
    "Metadata": {
        "ImageID": "sha256:" + "a" * 64,
        "OS": {"Family": "debian", "Name": "13.7"},
        "ImageConfig": {
            "os": "linux",
            "architecture": "amd64",
            "config": {
                "User": "65532:65532",
                "Labels": {
                    "org.opencontainers.image.title": "devsecops-app",
                    "org.opencontainers.image.version": "0123456789ab",
                    "org.opencontainers.image.revision": "0123456789abcdef",
                },
            },
        },
    },
    "Results": [{
        "Target": "image.tar (debian 13.7)",
        "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "libfoo", "InstalledVersion": "1", "FixedVersion": "2",
             "Severity": "HIGH", "Status": "fixed"},
            {"VulnerabilityID": "CVE-2", "PkgName": "libbar", "InstalledVersion": "1", "Severity": "LOW",
             "Status": "affected"},
        ],
    }],
}

GATE = {
    "decision": "fail",
    "policy": {"fail_on_severity": "CRITICAL", "fail_on_fixable_severity": "HIGH",
               "secrets": "any secret fails", "ignore_file": ".trivyignore"},
    "blocking": [{"kind": "vulnerability", "id": "CVE-1", "severity": "HIGH", "package": "libfoo",
                  "installed": "1", "fixed": "2", "target": "image.tar", "reason": "HIGH with fix available"}],
    "waived": [],
    "expired_waivers": [],
}


def write(directory, name, data):
    (directory / name).write_text(json.dumps(data))


def test_report_restates_gate_decision_and_counts(tmp_path):
    write(tmp_path, "trivy.json", TRIVY)
    write(tmp_path, "gate.json", GATE)
    text = report.render(tmp_path)
    assert "## Gate: FAIL" in text
    assert "| HIGH | CVE-1 | libfoo | 1 | 2 | HIGH with fix available |" in text
    assert "| HIGH | 1 | 1 |" in text
    assert "| LOW | 1 | 0 |" in text
    assert "`devsecops-app:0123456789ab`" in text
    assert "| Published | no |" in text


def test_report_shows_published_digest(tmp_path):
    write(tmp_path, "trivy.json", TRIVY)
    write(tmp_path, "publish.json", {"target": "jfrog", "repository": "docker-local/devsecops-app",
                                     "tag": "x", "digest": "sha256:" + "b" * 64,
                                     "config_digest": TRIVY["Metadata"]["ImageID"]})
    text = report.render(tmp_path)
    assert "`docker-local/devsecops-app@sha256:%s` (JFrog Artifactory)" % ("b" * 64) in text


def test_report_ignores_publish_result_of_another_image(tmp_path):
    write(tmp_path, "trivy.json", TRIVY)
    write(tmp_path, "publish.json", {"target": "local", "registry": "localhost:5050", "repository": "devsecops-app",
                                     "tag": "old", "digest": "sha256:" + "c" * 64,
                                     "config_digest": "sha256:" + "d" * 64})
    assert "| Published | no |" in report.render(tmp_path)


def test_report_with_missing_inputs_says_so(tmp_path):
    text = report.render(tmp_path)
    assert "## Gate: not run" in text
    assert "`trivy.json` not found." in text
    assert "`sbom.cdx.json` not found." in text
