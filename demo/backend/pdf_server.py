"""PDF tool server (MCP): image to PDF and PDF merge with the real iLovePDF API.

    python pdf_server.py

An ordinary third-party style MCP server. VAJRA launches it inside its OS jail, admits
its tool through the admission sandbox, and treats every file it produces as untrusted.

Environment:
    VAJRA_PDF_INCOMING     folder the tool may read its input files from (checked by VAJRA)
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


def ilovepdf(tool: str, inputs: list[Path], out: Path, **options: object) -> dict[str, object]:
    """Run one iLovePDF task (start, upload, process, download) on the given files."""
    key = os.environ.get("ILOVEPDF_PUBLIC_KEY", "").strip()
    if not key:
        raise RuntimeError("ILOVEPDF_PUBLIC_KEY is not set")
    with httpx.Client(timeout=TIMEOUT) as http:
        token = http.post(f"{API}/auth", json={"public_key": key}).raise_for_status().json()["token"]
        auth = {"Authorization": f"Bearer {token}"}
        start = http.get(f"{API}/start/{tool}", headers=auth).raise_for_status().json()
        server, task = start["server"], start["task"]
        files = []
        for path in inputs:
            with path.open("rb") as f:
                up = http.post(f"https://{server}/v1/upload", headers=auth, data={"task": task},
                               files={"file": (path.name, f)}).raise_for_status().json()
            files.append({"server_filename": up["server_filename"], "filename": path.name})
        http.post(f"https://{server}/v1/process", headers=auth,
                  json={"task": task, "tool": tool, "files": files, **options}).raise_for_status()
        resp = http.get(f"https://{server}/v1/download/{task}", headers=auth).raise_for_status()
        out.write_bytes(resp.content)
        return {"converter": "iLovePDF", "server": server, "remaining_credits": start.get("remaining_credits")}


def offline_images(images: list[Path], out: Path) -> dict[str, object]:
    """Backup for venues without internet: converts locally with Pillow."""
    from PIL import Image

    frames = [Image.open(p).convert("RGB") for p in images]
    frames[0].save(out, "PDF", save_all=True, append_images=frames[1:], resolution=150)
    return {"converter": "Offline (Pillow)", "server": "local"}


def offline_merge(pdfs: list[Path], out: Path) -> dict[str, object]:
    """Backup for venues without internet: merges locally with pypdf."""
    from pypdf import PdfWriter

    writer = PdfWriter()
    for p in pdfs:
        writer.append(str(p))
    with out.open("wb") as f:
        writer.write(f)
    return {"converter": "Offline (pypdf)", "server": "local"}


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
        if engine == "offline":
            info = offline_images(paths, out)
        else:
            info = ilovepdf("imagepdf", paths, out, orientation="portrait", margin=0, pagesize="fit", merge_after=True)
        return json.dumps({"file": out.name, "bytes": out.stat().st_size, **info})

    @app.tool()
    def merge_pdfs(files: list[str], engine: str = "ilovepdf") -> str:
        """Merge two or more PDF files, in the order given, into one PDF. Returns the output file name and details as JSON."""
        paths = [_inside(incoming, name) for name in files]
        if len(paths) < 2:
            raise ValueError("give at least two PDF files")
        out = output / "merged.pdf"
        info = offline_merge(paths, out) if engine == "offline" else ilovepdf("merge", paths, out)
        return json.dumps({"file": out.name, "bytes": out.stat().st_size, **info})

    return app


if __name__ == "__main__":
    build().run()
