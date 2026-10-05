"""Tests for the helpers in scripts/lib.sh, sourced and called from bash."""

import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parent.parent / "scripts" / "lib.sh"
HEX = "3" * 64

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None, reason="lib.sh needs bash and jq"
)


def bash(snippet, cwd=None, **env):
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(("ART_", "GITHUB_", "GIT_", "PUBLISH", "IMAGE_NAME", "LOCAL_REGISTRY"))}
    # Keep git away from the user's and the system's configuration.
    environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", **env)
    return subprocess.run(["bash", "-c", 'set -euo pipefail; source "$1"; shift; ' + snippet, "bash", str(LIB)],
                          cwd=cwd, env=environment, capture_output=True, text=True, check=False)


@pytest.mark.parametrize(
    "url, host",
    [
        ("https://example.jfrog.io", "example.jfrog.io"),
        ("https://example.jfrog.io/", "example.jfrog.io"),
        ("http://localhost:8081/artifactory", "localhost:8081"),
        ("example.jfrog.io", "example.jfrog.io"),
    ],
)
def test_art_host(url, host):
    proc = bash("art_host", ART_URL=url)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == host + "\n"


def test_jfrog_host_is_masked_in_github_actions():
    proc = bash("true", GITHUB_ACTIONS="true", ART_URL="https://example.jfrog.io/")
    assert proc.stdout == "::add-mask::example.jfrog.io\n"


def test_nothing_is_masked_outside_github_actions():
    assert bash("true", ART_URL="https://example.jfrog.io/").stdout == ""


@pytest.mark.parametrize(
    "publish, repo",
    [("local", "localhost:5050/devsecops-app"), ("jfrog", "example.jfrog.io/docker-local/devsecops-app")],
)
def test_destination_repo(publish, repo):
    proc = bash("destination_repo", PUBLISH=publish, ART_URL="https://example.jfrog.io")
    assert proc.stdout == repo + "\n", proc.stderr


def write_tarball(path, config):
    manifest = json.dumps([{"Config": config, "Layers": []}]).encode()
    with tarfile.open(path, "w") as tar:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))


@pytest.mark.parametrize("config", ["blobs/sha256/" + HEX, HEX + ".json"])  # Docker 25+, older Docker
def test_tarball_config_digest(tmp_path, config):
    write_tarball(tmp_path / "image.tar", config)
    proc = bash('tarball_config_digest "%s"' % (tmp_path / "image.tar"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "sha256:%s\n" % HEX


def test_tarball_config_digest_rejects_unexpected_config(tmp_path):
    write_tarball(tmp_path / "image.tar", "blobs/sha256/not-a-digest")
    assert bash('tarball_config_digest "%s"' % (tmp_path / "image.tar")).returncode != 0


def test_run_to_file_writes_output_of_a_successful_command(tmp_path):
    out = tmp_path / "sub" / "result.json"
    proc = bash('run_to_file "%s" echo "{}"' % out)
    assert proc.returncode == 0
    assert out.read_text() == "{}\n"


@pytest.mark.parametrize("command", ["false", "true"])  # fails / succeeds with no output
def test_run_to_file_leaves_nothing_behind_on_failure(tmp_path, command):
    out = tmp_path / "result.json"
    out.write_text("old result")
    proc = bash('run_to_file "%s" %s' % (out, command))
    assert proc.returncode != 0
    assert list(tmp_path.iterdir()) == []


@pytest.fixture
def repo(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True,
                   env=dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1"))
    return tmp_path


@pytest.mark.parametrize(
    "remote, label",
    [
        ("https://github.com/o/r.git", "https://github.com/o/r"),
        ("git@github.com:o/r.git", "https://github.com/o/r"),
        ("https://user:secret@github.com/o/r.git", "https://github.com/o/r"),
        ("https://user:p@ss@github.com/o/r", "https://github.com/o/r"),
        ("https://github.com/o/r@v1", "https://github.com/o/r@v1"),
    ],
)
def test_source_url_strips_credentials(repo, remote, label):
    bash('git remote add origin "%s"' % remote, cwd=repo)
    proc = bash("source_url", cwd=repo)
    assert proc.stdout == label + "\n", proc.stderr


def test_source_url_without_remote(repo):
    assert bash("source_url", cwd=repo).stdout == "unknown\n"


def test_source_url_in_github_actions(repo):
    bash('git remote add origin "https://user:secret@example.com/x.git"', cwd=repo)
    proc = bash("source_url", cwd=repo, GITHUB_SERVER_URL="https://github.com", GITHUB_REPOSITORY="o/r")
    assert proc.stdout == "https://github.com/o/r\n"
