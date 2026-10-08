"""A separate, real website for the live-fetch demo.

Serves the pages in demo/mock_web over HTTP so the web MCP server fetches them
for real (no file shortcuts):

    python -m demo.backend.site_server            # http://127.0.0.1:8090/setup

/setup is the AcmeTools setup guide (it contains the hidden-<div> test payload
from attack 2). Open it in a browser: the hidden part is invisible to people.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "mock_web"
ROUTES = {"/setup": "setup_guide.html"}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        name = ROUTES.get(self.path.rstrip("/") or "/")
        if self.path in ("/", ""):
            body = "".join(f'<li><a href="{p}">{p}</a></li>' for p in ROUTES).encode()
            self._send(200, b"<!doctype html><h1>Demo site</h1><ul>" + body + b"</ul>")
        elif name:
            self._send(200, (WEB / name).read_bytes())
        else:
            self._send(404, b"not found")

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="python -m demo.backend.site_server")
    parser.add_argument("--port", type=int, default=8090)
    port = parser.parse_args().port
    print(f"demo site on http://127.0.0.1:{port}/setup")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
