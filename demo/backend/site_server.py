"""A separate, real website for the live-fetch demo.

Serves the pages in demo/mock_web over HTTP so the web MCP server fetches them
for real (no file shortcuts):

    python -m demo.backend.site_server            # http://127.0.0.1:8090/setup

/downloads lists the Secure convert sample files as ordinary download links (for the
browser extension demo).

/setup is the AcmeTools setup guide (it contains the hidden-<div> test payload
from attack 2). Open it in a browser: the hidden part is invisible to people.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "mock_web"
SAMPLES = Path(__file__).resolve().parent.parent / "convert_samples"
ROUTES = {"/setup": "setup_guide.html", "/downloads": None}
TYPES = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg"}


def _samples() -> list[Path]:
    return sorted(p for p in SAMPLES.rglob("*") if p.suffix.lower() in TYPES)


def downloads_page() -> bytes:
    rows = []
    for p in _samples():
        safe = "_safe" in p.name
        rows.append(
            f'<tr><td><a href="/files/{p.parent.name}/{p.name}" target="_blank" rel="noopener">{p.name}</a></td>'
            f'<td>{p.parent.name}</td><td>{p.stat().st_size // 1024 or 1} KB</td>'
            f'<td class="{"ok" if safe else "bad"}">{"expected: delivered" if safe else "expected: burned"}</td></tr>'
        )
    return ("""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Document downloads</title><style>
body{font-family:Inter,system-ui,Segoe UI,sans-serif;margin:0;background:#f5f7fa;color:#0f172a}
header{background:#0b1220;color:#fff;padding:28px 32px}header h1{margin:0;font-size:24px}header p{margin:6px 0 0;color:#94a3b8}
main{max-width:900px;margin:24px auto;padding:0 16px}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e8ef;border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #eef2f7;font-size:14px}th{background:#f8fafc;color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
a{color:#2563eb;font-weight:600;text-decoration:none}a:hover{text-decoration:underline}.ok{color:#047857}.bad{color:#b91c1c}
.note{font-size:13px;color:#64748b;margin-top:14px}
</style></head><body><header><h1>Document downloads</h1><p>A plain website serving files. Click one with the VAJRA extension installed.</p></header>
<main><table><tr><th>File</th><th>Folder</th><th>Size</th><th>With VAJRA</th></tr>""" + "".join(rows) + """</table>
<p class="note">The unsafe files are harmless test files: each carries a "VAJRA TEST" marker where a clean file has nothing.</p></main></body></html>""").encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        name = ROUTES.get(self.path.rstrip("/") or "/")
        if self.path.startswith("/files/"):
            match = {f"/files/{p.parent.name}/{p.name}": p for p in _samples()}.get(self.path)
            if match is None:
                self._send(404, b"not found")
                return
            self._send(200, match.read_bytes(), TYPES[match.suffix.lower()], match.name)
        elif self.path.rstrip("/") == "/downloads":
            self._send(200, downloads_page())
        elif self.path in ("/", ""):
            body = "".join(f'<li><a href="{p}">{p}</a></li>' for p in ROUTES).encode()
            self._send(200, b"<!doctype html><h1>Demo site</h1><ul>" + body + b"</ul>")
        elif name:
            self._send(200, (WEB / name).read_bytes())
        else:
            self._send(404, b"not found")

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8", attachment: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="python -m demo.backend.site_server")
    parser.add_argument("--port", type=int, default=8090)
    port = parser.parse_args().port
    print(f"demo site on http://127.0.0.1:{port}/setup")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
