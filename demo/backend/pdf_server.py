"""PDF tool server (MCP): converts images to a PDF with the real iLovePDF API.

    python pdf_server.py

An ordinary third-party style MCP server. VAJRA launches it inside its OS jail, admits
its tool through the admission sandbox, and treats every file it produces as untrusted.

Environment:
    VAJRA_PDF_INCOMING     folder the tool may read images from (cleaned by VAJRA)
    VAJRA_PDF_OUTPUT       folder the tool writes its PDF into (VAJRA's quarantine)
    ILOVEPDF_PUBLIC_KEY    iLovePDF developer project key (developer.ilovepdf.com)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
from mcp.server.mcpserver import MCPServer

API = "https://api.ilovepdf.com/v1"
TIMEOUT = httpx.Timeout(60.0, connect=15.0)


def _inside(folder: Path, name: str) -> Path:
    target = (folder / name).resolve()
    if not target.is_relative_to(folder.resolve()) or not target.is_file():
        raise ValueError(f"no such input file {name!r}")
    return target


def ilovepdf(images: list[Path], out: Path) -> dict[str, object]:
    key = os.environ.get("ILOVEPDF_PUBLIC_KEY", "").strip()
    if not key:
        raise RuntimeError("ILOVEPDF_PUBLIC_KEY is not set")
    with httpx.Client(timeout=TIMEOUT) as http:
        token = http.post(f"{API}/auth", json={"public_key": key}).raise_for_status().json()["token"]
        auth = {"Authorization": f"Bearer {token}"}
        start = http.get(f"{API}/start/imagepdf", headers=auth).raise_for_status().json()
        server, task = start["server"], start["task"]
        files = []
        for img in images:
            with img.open("rb") as f:
                up = http.post(f"https://{server}/v1/upload", headers=auth, data={"task": task},
                               files={"file": (img.name, f)}).raise_for_status().json()
            files.append({"server_filename": up["server_filename"], "filename": img.name})
        http.post(f"https://{server}/v1/process", headers=auth, json={
            "task": task, "tool": "imagepdf", "files": files,
            "orientation": "portrait", "margin": 0, "pagesize": "fit", "merge_after": True,
        }).raise_for_status()
        resp = http.get(f"https://{server}/v1/download/{task}", headers=auth).raise_for_status()
        out.write_bytes(resp.content)
        return {"converter": "iLovePDF", "server": server, "remaining_credits": start.get("remaining_credits")}


def offline(images: list[Path], out: Path) -> dict[str, object]:
    """Backup for venues without internet: converts locally with Pillow."""
    from PIL import Image

    frames = [Image.open(p).convert("RGB") for p in images]
    frames[0].save(out, "PDF", save_all=True, append_images=frames[1:], resolution=150)
    return {"converter": "Offline (Pillow)", "server": "local"}


def build() -> MCPServer:
    app = MCPServer("pdf")
    incoming = Path(os.environ["VAJRA_PDF_INCOMING"])
    output = Path(os.environ["VAJRA_PDF_OUTPUT"])

    @app.tool()
    def image_to_pdf(images: list[str], engine: str = "ilovepdf") -> str:
        """Convert one or more images into a single PDF. Returns the output file name and details as JSON."""
        paths = [_inside(incoming, name) for name in images]
        if not paths:
            raise ValueError("no images given")
        out = output / "converted.pdf"
        info = (offline if engine == "offline" else ilovepdf)(paths, out)
        return json.dumps({"file": out.name, "bytes": out.stat().st_size, **info})

    return app


if __name__ == "__main__":
    build().run()
