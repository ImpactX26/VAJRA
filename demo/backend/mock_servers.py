"""Mock upstream MCP servers for the demo. Run one per role:

    python mock_servers.py --role files|web|mail

They are ordinary, honest MCP servers: the danger is in the *content* they
serve (poisoned files and web pages), exactly as with real servers.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.mcpserver import MCPServer

DEMO_DIR = Path(__file__).resolve().parent.parent
WORKSPACE = DEMO_DIR / "mock_workspace"
WEB = DEMO_DIR / "mock_web"


def files_server() -> MCPServer:
    app = MCPServer("files")

    @app.tool()
    def list_files() -> str:
        """List the files in Alice's workspace."""
        return "\n".join(sorted(p.relative_to(WORKSPACE).as_posix() for p in WORKSPACE.rglob("*") if p.is_file()))

    @app.tool()
    def read_file(path: str) -> str:
        """Read a text file from Alice's workspace by relative path."""
        target = (WORKSPACE / path).resolve()
        if not target.is_relative_to(WORKSPACE) or not target.is_file():
            return f"error: no such file {path!r}"
        return target.read_text(encoding="utf-8")

    return app


def web_server() -> MCPServer:
    app = MCPServer("web")
    pages: dict[str, str] = json.loads((WEB / "pages.json").read_text(encoding="utf-8"))

    @app.tool()
    def fetch_url(url: str) -> str:
        """Fetch a web page and return its raw HTML."""
        name = pages.get(url.rstrip("/"))
        return (WEB / name).read_text(encoding="utf-8") if name else f"error: 404 for {url}"

    return app


def mail_server() -> MCPServer:
    app = MCPServer("mail")
    outbox = Path(os.environ["VAJRA_OUTBOX"])

    @app.tool()
    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email from Alice's account."""
        record = {"to": to, "subject": subject, "body": body, "sent_at": datetime.now(UTC).isoformat()}
        with outbox.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return f"Email sent to {to}."

    return app


ROLES = {"files": files_server, "web": web_server, "mail": mail_server}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=ROLES, required=True)
    ROLES[parser.parse_args().role]().run()
