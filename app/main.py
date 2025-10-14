from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"up!")
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
