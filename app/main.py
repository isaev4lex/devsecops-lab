"""Small HTTP service that the pipeline builds, scans and publishes.

Endpoints:
  GET /health   200 {"status": "ok"}
  GET /version  200 {"revision": "<git revision baked in at build time>"}
Anything else returns 404.

`python main.py healthcheck` probes /health on the local port and exits 0 or 1.
The container HEALTHCHECK uses it because the runtime image has no shell or curl.
"""

import json
import os
import signal
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

REVISION = os.environ.get("APP_REVISION", "unknown")
DEFAULT_PORT = 3000

# C0 and C1 control characters, written as \xNN in log lines (as the stdlib
# handler does), so a crafted request line cannot forge log lines or send
# terminal escape sequences to whoever reads the logs.
_CONTROL_CHARS = str.maketrans({c: "\\x%02x" % c for c in [*range(0x20), *range(0x7F, 0xA0)]})


def _routes():
    return {
        "/health": {"status": "ok"},
        "/version": {"revision": REVISION},
    }


class Handler(BaseHTTPRequestHandler):
    # Do not advertise the Python version in the Server header.
    server_version = "devsecops-app"
    sys_version = ""

    def _respond(self, include_body):
        payload = _routes().get(urlsplit(self.path).path)
        status = 200 if payload is not None else 404
        body = json.dumps(payload if payload is not None else {"error": "not found"}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def do_GET(self):
        self._respond(include_body=True)

    def do_HEAD(self):
        self._respond(include_body=False)

    def log_message(self, format, *args):
        # One line per request on stdout (the default writes to stderr). Overriding
        # this drops the stdlib's control-character escaping, so it is redone here.
        message = (format % args).translate(_CONTROL_CHARS)
        sys.stdout.write("%s %s\n" % (self.client_address[0], message))


def make_server(host, port):
    return ThreadingHTTPServer((host, port), Handler)


def healthcheck(port, timeout=2.0):
    url = "http://127.0.0.1:%d/health" % port
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return 0 if resp.status == 200 else 1
    except OSError:
        return 1


def main(argv):
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    if argv[1:] == ["healthcheck"]:
        return healthcheck(port)
    if argv[1:]:
        sys.stderr.write("usage: main.py [healthcheck]\n")
        return 2

    host = os.environ.get("HOST", "0.0.0.0")
    server = make_server(host, port)
    # docker stop sends SIGTERM; exit cleanly instead of being killed after the grace period.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print("listening on %s:%d revision=%s" % (host, port, REVISION), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
