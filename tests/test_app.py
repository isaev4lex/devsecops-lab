import json
import socket
import threading
import time
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


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_other_methods_are_not_implemented(port, method):
    status, _, _ = request(port, "/health", method=method)
    assert status == 501


def test_connections_have_a_socket_timeout():
    assert main.Handler.timeout == main.REQUEST_TIMEOUT
    assert 0 < main.REQUEST_TIMEOUT <= 30


def test_idle_connection_is_closed(port, monkeypatch):
    # Shortened so the test is quick; the default is checked above.
    monkeypatch.setattr(main.Handler, "timeout", 0.5)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        started = time.monotonic()
        assert sock.recv(1024) == b""  # the server closed the connection
        assert time.monotonic() - started < 4


def test_log_line_escapes_control_characters(port, capsys):
    # urllib refuses control characters in a URL, so send the request line by hand.
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(b"GET /\x1b[2J\x08x HTTP/1.0\r\n\r\n")
        assert sock.recv(1024).startswith(b"HTTP/1.0 404")
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x08" not in out
    assert "/\\x1b[2J\\x08x" in out


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
