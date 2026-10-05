import json
import socket
import threading
import urllib.error
import urllib.request

import pytest

from app import main


@pytest.fixture
def port():
    server = main.make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def request(port, path, method="GET"):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read()


def test_health_returns_ok_json(port):
    status, headers, body = request(port, "/health")
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    assert headers["Cache-Control"] == "no-store"
    assert json.loads(body) == {"status": "ok"}


def test_health_ignores_query_string(port):
    status, _, body = request(port, "/health?probe=lb")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_head_health_has_headers_but_no_body(port):
    status, headers, body = request(port, "/health", method="HEAD")
    assert status == 200
    assert int(headers["Content-Length"]) > 0
    assert body == b""


def test_version_reports_build_revision(port, monkeypatch):
    monkeypatch.setattr(main, "REVISION", "0123456789ab")
    status, _, body = request(port, "/version")
    assert status == 200
    assert json.loads(body) == {"revision": "0123456789ab"}


@pytest.mark.parametrize("path", ["/", "/healthz", "/health/../etc/passwd"])
def test_unknown_paths_return_404(port, path):
    status, _, body = request(port, path)
    assert status == 404
    assert json.loads(body) == {"error": "not found"}


def test_server_header_does_not_leak_python_version(port):
    _, headers, _ = request(port, "/health")
    assert "Python" not in headers["Server"]


def test_healthcheck_command_passes_against_running_server(port):
    assert main.healthcheck(port) == 0


def test_healthcheck_command_fails_when_nothing_listens():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
    assert main.healthcheck(free_port, timeout=1) == 1


def test_unknown_argument_is_rejected(capsys):
    assert main.main(["main.py", "bogus"]) == 2
    assert "usage" in capsys.readouterr().err
