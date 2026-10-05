import os
import shutil
from types import SimpleNamespace

import pytest

# Stand-in for `docker`: records each call (one line of arguments) and answers
# the few subcommands the stage scripts use. Behaviour is set through
# DOCKER_STUB_* variables in the environment the script runs with.
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


@pytest.fixture
def docker_stub(tmp_path):
    """Environment with the docker stub first on PATH and no pipeline settings
    inherited from the caller (a developer's .env exported by make, or CI)."""
    if shutil.which("bash") is None or shutil.which("jq") is None:
        pytest.skip("the scripts need bash and jq")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "docker"
    stub.write_text(DOCKER_STUB)
    stub.chmod(0o755)
    log = tmp_path / "docker.log"
    log.touch()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("ART_", "GITHUB_", "FAIL_ON_", "GATE_", "PUBLISH", "TRIVY_", "SARIF_", "DOCKER"))}
    env.update(PATH=str(bin_dir) + os.pathsep + env.get("PATH", ""),
               DOCKER_STUB_LOG=str(log), DOCKER_STUB_RUN_OUTPUT="")
    return SimpleNamespace(env=env, calls=lambda: log.read_text().splitlines())
