"""Tests for scripts/gate.sh, the only place that decides pass or fail.

Each test writes a small Trivy-shaped JSON report, runs the real script with a
fixed date, and checks the exit code and the gate.json it writes.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parent.parent / "scripts" / "gate.sh"
TODAY = "2026-06-01"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None, reason="gate.sh needs bash and jq"
)


def vuln(vid, severity, fixed=""):
    return {
        "VulnerabilityID": vid,
        "PkgName": "libfoo",
        "InstalledVersion": "1.0-1",
        "FixedVersion": fixed,
        "Status": "fixed" if fixed else "affected",
        "Severity": severity,
    }


def secret(rule_id="aws-access-key-id"):
    return {"RuleID": rule_id, "Category": "AWS", "Severity": "CRITICAL", "Title": "AWS Access Key ID", "StartLine": 3}


def scan(*vulns, secrets=()):
    results = [{"Target": "image.tar (debian 13.7)", "Class": "os-pkgs", "Type": "debian",
                "Vulnerabilities": list(vulns)}]
    if secrets:
        results.append({"Target": "/app/settings.py", "Class": "secret", "Secrets": list(secrets)})
    return {"SchemaVersion": 2, "ArtifactName": "image.tar", "ArtifactType": "container_image", "Results": results}


def run_gate(tmp_path, report, ignore=None, **env):
    scan_file = tmp_path / "trivy.json"
    scan_file.write_text(json.dumps(report))
    args = ["bash", str(GATE), str(scan_file)]
    if ignore is not None:
        ignore_file = tmp_path / ".trivyignore"
        ignore_file.write_text(ignore)
        args.append(str(ignore_file))
    environment = {k: v for k, v in os.environ.items()
                   if k not in ("FAIL_ON_SEVERITY", "FAIL_ON_FIXABLE_SEVERITY", "GATE_RESULT", "GITHUB_ACTIONS")}
    environment.update(GATE_TODAY=TODAY, **env)
    proc = subprocess.run(args, capture_output=True, text=True, env=environment, check=False)
    result_file = tmp_path / "gate.json"
    result = json.loads(result_file.read_text()) if result_file.exists() else None
    return proc, result


@pytest.mark.parametrize(
    "findings, expected_exit",
    [
        ([], 0),
        ([vuln("CVE-1", "LOW"), vuln("CVE-2", "MEDIUM", fixed="1.1")], 0),
        ([vuln("CVE-1", "HIGH")], 0),                    # HIGH with no fix: reported, not blocking
        ([vuln("CVE-1", "HIGH", fixed="1.0-2")], 2),     # HIGH with a fix: blocking
        ([vuln("CVE-1", "CRITICAL")], 2),                # CRITICAL blocks with or without a fix
        ([vuln("CVE-1", "CRITICAL", fixed="1.0-2")], 2),
    ],
)
def test_default_policy(tmp_path, findings, expected_exit):
    proc, result = run_gate(tmp_path, scan(*findings))
    assert proc.returncode == expected_exit, proc.stdout + proc.stderr
    assert result["decision"] == ("pass" if expected_exit == 0 else "fail")


def test_counts_by_severity_and_fix_status(tmp_path):
    _, result = run_gate(tmp_path, scan(vuln("A", "HIGH"), vuln("B", "HIGH", fixed="2"), vuln("C", "LOW")))
    assert result["counts"]["HIGH"] == {"total": 2, "fixable": 1}
    assert result["counts"]["LOW"] == {"total": 1, "fixable": 0}
    assert [f["id"] for f in result["blocking"]] == ["B"]


def test_report_without_results_passes(tmp_path):
    proc, result = run_gate(tmp_path, {"SchemaVersion": 2, "ArtifactName": "scratch.tar"})
    assert proc.returncode == 0
    assert result["blocking"] == []


def test_stricter_threshold_from_environment(tmp_path):
    proc, result = run_gate(tmp_path, scan(vuln("CVE-1", "HIGH")), FAIL_ON_SEVERITY="HIGH")
    assert proc.returncode == 2
    assert result["policy"]["fail_on_severity"] == "HIGH"


def test_fixable_rule_can_be_disabled(tmp_path):
    proc, _ = run_gate(tmp_path, scan(vuln("CVE-1", "HIGH", fixed="2")), FAIL_ON_FIXABLE_SEVERITY="NONE")
    assert proc.returncode == 0


def test_secret_in_image_fails(tmp_path):
    proc, result = run_gate(tmp_path, scan(secrets=[secret()]))
    assert proc.returncode == 2
    assert result["secrets"] == 1
    assert result["blocking"][0]["kind"] == "secret"


def test_active_waiver_unblocks_finding(tmp_path):
    ignore = "# reason, owner, ticket\nCVE-1 exp:2026-12-31\n"
    proc, result = run_gate(tmp_path, scan(vuln("CVE-1", "CRITICAL")), ignore=ignore)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert result["waived"][0]["id"] == "CVE-1"
    assert result["waived"][0]["waived_until"] == "2026-12-31"


def test_waiver_applies_through_its_expiry_date(tmp_path):
    proc, _ = run_gate(tmp_path, scan(vuln("CVE-1", "CRITICAL")), ignore="CVE-1 exp:%s\n" % TODAY)
    assert proc.returncode == 0


def test_expired_waiver_blocks_again(tmp_path):
    proc, result = run_gate(tmp_path, scan(vuln("CVE-1", "CRITICAL")), ignore="CVE-1 exp:2026-05-31\n")
    assert proc.returncode == 2
    assert result["expired_waivers"] == [{"id": "CVE-1", "expires": "2026-05-31", "line": 1}]
    assert "expired" in proc.stdout


def test_secret_can_be_waived_by_rule_id(tmp_path):
    proc, _ = run_gate(tmp_path, scan(secrets=[secret("test-key")]), ignore="test-key exp:2026-12-31\n")
    assert proc.returncode == 0


def test_unused_waiver_is_reported(tmp_path):
    proc, result = run_gate(tmp_path, scan(), ignore="CVE-9 exp:2026-12-31\n")
    assert proc.returncode == 0
    assert result["unused_waivers"][0]["id"] == "CVE-9"
    assert "matches no blocking finding" in proc.stdout


def test_missing_ignore_file_is_allowed(tmp_path):
    scan_file = tmp_path / "trivy.json"
    scan_file.write_text(json.dumps(scan()))
    proc = subprocess.run(["bash", str(GATE), str(scan_file), str(tmp_path / "absent")],
                          capture_output=True, text=True, env={**os.environ, "GATE_TODAY": TODAY}, check=False)
    assert proc.returncode == 0


@pytest.mark.parametrize(
    "ignore, message",
    [
        ("CVE-1\n", "has no expiry"),
        ("CVE-1 exp:2026-02-30\n", "invalid date"),
        ("CVE-1 exp:31-12-2026\n", "invalid date"),
        ("CVE-1 until:2026-12-31\n", "unexpected"),
    ],
)
def test_malformed_waivers_are_configuration_errors(tmp_path, ignore, message):
    proc, _ = run_gate(tmp_path, scan(vuln("CVE-1", "CRITICAL")), ignore=ignore)
    assert proc.returncode == 1
    assert message in proc.stderr


def test_invalid_threshold_is_a_configuration_error(tmp_path):
    proc, _ = run_gate(tmp_path, scan(), FAIL_ON_SEVERITY="SEVERE")
    assert proc.returncode == 1
    assert "FAIL_ON_SEVERITY" in proc.stderr


def test_non_trivy_input_is_rejected(tmp_path):
    proc, _ = run_gate(tmp_path, {"hello": "world"})
    assert proc.returncode == 1
    assert "not a Trivy JSON report" in proc.stderr
