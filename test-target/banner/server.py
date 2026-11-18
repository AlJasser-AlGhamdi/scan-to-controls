from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BANNERS = {
    "/current": {"Server": "nginx/1.30.5"},
    "/outdated": {"Server": "nginx/1.30.1"},
    "/outdated-recent": {"Server": "nginx/1.30.4"},
    "/eol": {"Server": "Apache/2.2.15"},
    "/php-eol": {"X-Powered-By": "PHP/8.1.2"},
    "/hidden": {"Server": "nginx"},
    "/cycle-only": {"Server": "Apache/2.4"},
}


class Handler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        self.send_response_only(code, message)

    def do_GET(self):
        headers = BANNERS.get(self.path)
        self.send_response(200 if headers is not None else 404)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        body = b"banner case\n"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
