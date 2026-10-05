"""Tests for the checks that stand between a scan and a push.

scripts/publish.sh and scripts/scan_trivy.sh run for real against files in a
temporary build directory. `docker` is replaced on PATH by a stub that records
its arguments and answers the few subcommands the scripts use, so no Docker
daemon, registry or credentials are involved.
"""

import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
IMAGE_ID = "sha256:" + "1" * 64
OTHER_IMAGE_ID = "sha256:" + "2" * 64
PUSHED_DIGEST = "sha256:" + "e" * 64

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None, reason="the scripts need bash and jq"
)

DOCKER_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >>"$DOCKER_STUB_LOG"
case "$1" in
  buildx)
    case "$2" in
      version) [ -z "${DOCKER_STUB_NO_BUILDX:-}" ] ;;
      imagetools) printf '{"config": {"digest": "%s"}}\\n' "$DOCKER_STUB_CONFIG" ;;
      *) exit 1 ;;
    esac
    ;;
  load | tag | logout) ;;
  login) cat >/dev/null ;;
  push) printf 'test: digest: %s size: 1234\\n' "$DOCKER_STUB_DIGEST" ;;
  run) printf '%s\\n' "$DOCKER_STUB_RUN_OUTPUT" ;;
  *) exit 1 ;;
esac
"""


def trivy_report(image_id=IMAGE_ID, severity="LOW"):
    vuln = {"VulnerabilityID": "CVE-1", "PkgName": "libfoo", "InstalledVersion": "1",
            "FixedVersion": "", "Severity": severity}
    return {"SchemaVersion": 2, "Metadata": {"ImageID": image_id},
            "Results": [{"Target": "image.tar (debian 13.7)", "Vulnerabilities": [vuln]}]}


def write_tarball(path, config_hex):
    # The part of a `docker save` tarball that publish.sh reads.
    manifest = json.dumps([{"Config": "blobs/sha256/" + config_hex, "Layers": []}]).encode()
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))


@pytest.fixture
def ws(tmp_path):
    out = tmp_path / "build"
    out.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "docker"
    stub.write_text(DOCKER_STUB)
    stub.chmod(0o755)
    log = tmp_path / "docker.log"
    log.touch()

    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ART_", "GITHUB_", "FAIL_ON_", "GATE_", "PUBLISH", "TRIVY_", "SARIF_"))}
    env.update(
        PATH=str(bin_dir) + os.pathsep + env.get("PATH", ""),
        OUT=str(out),
        IMAGE_NAME="devsecops-app",
        REV="test",
        PUBLISH="jfrog",
        ART_URL="https://example.jfrog.io",
        ART_USER="ci",
        ART_TOKEN="test-token",
        DOCKER_STUB_LOG=str(log),
        DOCKER_STUB_CONFIG=IMAGE_ID,
        DOCKER_STUB_DIGEST=PUSHED_DIGEST,
        DOCKER_STUB_RUN_OUTPUT="",
    )
    write_tarball(out / "image.tar", IMAGE_ID.split(":")[1])
    (out / "trivy.json").write_text(json.dumps(trivy_report()))
    return SimpleNamespace(tmp=tmp_path, out=out, env=env, log=log)


def run(ws, script, *args):
    return subprocess.run(["bash", str(SCRIPTS / script), *args], cwd=ws.tmp, env=ws.env,
                          capture_output=True, text=True, check=False)


def gate(ws):
    return run(ws, "gate.sh", str(ws.out / "trivy.json"))


def docker_calls(ws):
    return ws.log.read_text().splitlines()


def pushed(ws):
    return any(call.split()[0] in ("load", "push") for call in docker_calls(ws))


def test_publishes_the_gated_and_scanned_image(ws):
    assert gate(ws).returncode == 0
    proc = run(ws, "publish.sh")
    assert proc.returncode == 0, proc.stderr
    assert "push example.jfrog.io/docker-local/devsecops-app:test" in docker_calls(ws)
    published = json.loads((ws.out / "publish.json").read_text())
    assert published == {"target": "jfrog", "repository": "docker-local/devsecops-app", "tag": "test",
                         "digest": PUSHED_DIGEST, "config_digest": IMAGE_ID}


def test_refuses_without_a_gate_result(ws):
    proc = run(ws, "publish.sh")
    assert proc.returncode == 1
    assert "no gate result" in proc.stderr
    assert not pushed(ws)


def test_refuses_when_the_gate_failed(ws):
    (ws.out / "trivy.json").write_text(json.dumps(trivy_report(severity="CRITICAL")))
    assert gate(ws).returncode == 2
    proc = run(ws, "publish.sh")
    assert proc.returncode == 1
    assert "gate decision is 'fail'" in proc.stderr
    assert not pushed(ws)


def test_refuses_a_pass_from_an_earlier_scan(ws):
    # Same image, but the scan was replaced after the gate ran (newer DB, new CRITICAL).
    assert gate(ws).returncode == 0
    (ws.out / "trivy.json").write_text(json.dumps(trivy_report(severity="CRITICAL")))
    proc = run(ws, "publish.sh")
    assert proc.returncode == 1
    assert "not computed from the current" in proc.stderr
    assert not pushed(ws)


def test_refuses_a_tarball_that_was_not_scanned(ws):
    (ws.out / "trivy.json").write_text(json.dumps(trivy_report(image_id=OTHER_IMAGE_ID)))
    assert gate(ws).returncode == 0
    proc = run(ws, "publish.sh")
    assert proc.returncode == 1
    assert "is not the scanned image" in proc.stderr
    assert not pushed(ws)


def test_fails_when_the_registry_returns_another_image(ws):
    ws.env["DOCKER_STUB_CONFIG"] = OTHER_IMAGE_ID
    assert gate(ws).returncode == 0
    proc = run(ws, "publish.sh")
    assert proc.returncode == 1
    assert "expected the scanned image" in proc.stderr
    assert not (ws.out / "publish.json").exists()


def test_publish_none_pushes_nothing(ws):
    ws.env["PUBLISH"] = "none"
    proc = run(ws, "publish.sh")
    assert proc.returncode == 0
    assert json.loads((ws.out / "publish.json").read_text()) == {"target": "none"}
    assert docker_calls(ws) == []


def test_new_scan_removes_results_of_the_previous_scan(ws):
    for name in ("gate.json", "trivy.sarif", "publish.json", "report.md", "sbom.cdx.json"):
        (ws.out / name).write_text("{}")
    ws.env["TRIVY_CACHE_DIR"] = str(ws.tmp / "cache")
    ws.env["DOCKER_STUB_RUN_OUTPUT"] = json.dumps(trivy_report())
    proc = run(ws, "scan_trivy.sh", str(ws.out / "image.tar"), str(ws.out / "trivy.json"))
    assert proc.returncode == 0, proc.stderr
    remaining = sorted(p.name for p in ws.out.iterdir())
    # The SBOM is made from the tarball, not from the scan, so it stays.
    assert remaining == ["image.tar", "sbom.cdx.json", "trivy.json"]
