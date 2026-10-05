"""Tests for scripts/to_sarif.sh, with `trivy convert` answered by the docker stub."""

import json
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def result(rule, package):
    # Shape of a result from `trivy convert --format sarif` for an OS package.
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": "Package: %s\nInstalled Version: 1.0" % package},
        "locations": [{
            "physicalLocation": {"artifactLocation": {"uri": "image.tar"}, "region": {"startLine": 1}},
            "message": {"text": "/in/image.tar: %s@1.0" % package},
        }],
    }


TRIVY_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Trivy", "rules": []}},
        "results": [result("CVE-1", "libfoo"), result("CVE-1", "libbar"), result("CVE-2", "libfoo")],
    }],
}


def test_results_point_at_the_from_line_with_a_fingerprint_each(tmp_path, docker_stub):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("# base image\n\nFROM scratch\n")
    scan = tmp_path / "trivy.json"
    scan.write_text("{}")
    out = tmp_path / "trivy.sarif"
    env = dict(docker_stub.env, DOCKERFILE=str(dockerfile), DOCKER_STUB_RUN_OUTPUT=json.dumps(TRIVY_SARIF))

    proc = subprocess.run(["bash", str(SCRIPTS / "to_sarif.sh"), str(scan), str(out)],
                          cwd=tmp_path, env=env, capture_output=True, text=True, check=False)

    assert proc.returncode == 0, proc.stderr
    assert "WARN" not in proc.stderr
    results = json.loads(out.read_text())["runs"][0]["results"]
    # One CVE in two packages stays two results with different fingerprints.
    assert [r["partialFingerprints"]["primaryLocationLineHash"] for r in results] == [
        "CVE-1|/in/image.tar: libfoo@1.0",
        "CVE-1|/in/image.tar: libbar@1.0",
        "CVE-2|/in/image.tar: libfoo@1.0",
    ]
    for r in results:
        assert r["locations"][0]["physicalLocation"] == {
            "artifactLocation": {"uri": str(dockerfile)},
            "region": {"startLine": 3, "startColumn": 1, "endLine": 3, "endColumn": 1},
        }
