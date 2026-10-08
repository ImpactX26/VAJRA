"""Secure convert: image to PDF through a real third-party tool (iLovePDF), with VAJRA in between.

    user image -> image check (jailed) -> clean copy -> pdf tool via MCP (jailed, admitted)
               -> quarantine -> PDF scan (jailed) -> burn | deliver to the user's device

Nothing the tool returns reaches the user until the file sandbox has passed it. A file
that fails is burned: overwritten and deleted, leaving only its fingerprint in the audit trail.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import mcp_types as types

from vajra.config import UpstreamConfig
from vajra.isolation import Limits, jail_command
from vajra.proxy import UpstreamManager

from .audit_trail import TRAIL

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".vajra-files"
DELIVERED = WORK / "delivered"
FILESCAN = str(ROOT / "src" / "vajra" / "filescan.py")
PDF_SERVER = str(Path(__file__).with_name("pdf_server.py"))
SCAN_LIMITS = Limits(memory_mb=768, cpu_seconds=60, max_processes=3)
TOOL_LIMITS = Limits(memory_mb=768, cpu_seconds=120, max_processes=3)
KEEP_SECONDS = 30 * 60
MAX_IMAGES = 10
MAX_UPLOAD = 15 * 1024 * 1024
ENGINES = ("ilovepdf", "offline")

TAMPER_TESTS = {
    "none": "None: deliver what the tool returns",
    "script": "Script added to the PDF",
    "hidden_text": "Invisible text layer added",
    "attachment": "Hidden file attached",
    "trailing": "Data appended after the end of the file",
}


def ilovepdf_ready() -> bool:
    return bool(os.environ.get("ILOVEPDF_PUBLIC_KEY", "").strip())


def burn(path: Path) -> None:
    """Overwrite, then delete: a burned file is not left recoverable in the work folder."""
    if path.is_file():
        size = path.stat().st_size
        with path.open("r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
        path.unlink()


def _burn_tree(folder: Path) -> None:
    for p in sorted(folder.rglob("*"), reverse=True):
        if p.is_file():
            burn(p)
        elif p.is_dir():
            p.rmdir()
    if folder.exists():
        folder.rmdir()


def cleanup_old() -> None:
    now = time.time()
    if DELIVERED.is_dir():
        for p in DELIVERED.iterdir():
            if now - p.stat().st_mtime > KEEP_SECONDS:
                p.unlink(missing_ok=True)


def _scan(args: list[str]) -> dict[str, Any]:
    """Run the file scanner inside the OS jail. A crash or timeout counts as unsafe."""
    cmd, argv = jail_command(sys.executable, [FILESCAN, *args], SCAN_LIMITS)
    try:
        proc = subprocess.run([cmd, *argv], capture_output=True, timeout=120, env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        return json.loads(proc.stdout.decode("utf-8"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        return {"safe": False, "checks": [{"name": "Scanner", "ok": False, "detail": f"scan did not finish ({type(e).__name__})"}], "removed": []}


def tamper(path: Path, how: str) -> None:
    """Test only: change the tool's output in transit, as a compromised converter or network could."""
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import ArrayObject, DecodedStreamObject, DictionaryObject, NameObject

    if how == "trailing":
        with path.open("ab") as f:
            f.write(b"\nVAJRA TEST DATA AFTER END OF FILE\n" * 64)
        return
    writer = PdfWriter(clone_from=PdfReader(path))
    if how == "script":
        writer.add_js('app.alert("VAJRA test script");')
    elif how == "attachment":
        writer.add_attachment("notes.txt", b"VAJRA test attachment")
    elif how == "hidden_text":
        page = writer.pages[0]
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        resources = page["/Resources"].get_object()
        resources[NameObject("/Font")] = DictionaryObject({NameObject("/FV"): writer._add_object(font)})
        text = DecodedStreamObject()
        text.set_data(b"BT /FV 1 Tf 3 Tr 5 5 Td (VAJRA test marker: text that is not in the image) Tj ET")  # 3 Tr = invisible
        existing = page["/Contents"]
        parts = list(existing.get_object()) if isinstance(existing.get_object(), ArrayObject) else [existing]
        page[NameObject("/Contents")] = ArrayObject([*parts, writer._add_object(text)])
    with path.open("wb") as f:
        writer.write(f)


def _text(r: types.CallToolResult) -> str:
    return "".join(b.text for b in r.content if isinstance(b, types.TextContent))


def _safe_name(name: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).stem)[:60].strip("._") or "image"
    return stem


async def convert(uploads: list[tuple[str, bytes]], engine: str, tamper_with: str) -> dict[str, Any]:
    cleanup_old()
    job = secrets.token_hex(6)
    folder = WORK / job
    incoming, clean, quarantine = folder / "incoming", folder / "clean", folder / "quarantine"
    for d in (incoming, clean, quarantine, DELIVERED):
        d.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []
    report: dict[str, Any] = {"job": job, "engine": engine, "tamper": tamper_with, "steps": steps}

    def step(sid: str, title: str, ok: bool, detail: str, **extra: Any) -> bool:
        steps.append({"id": sid, "title": title, "ok": ok, "detail": detail, **extra})
        return ok

    def finish(verdict: str, reason: str) -> dict[str, Any]:
        report.update(verdict=verdict, reason=reason)
        TRAIL.record("file.verdict", job=job, verdict=verdict, reason=reason)
        return report

    try:
        # 1. Receive -----------------------------------------------------------
        if not uploads or len(uploads) > MAX_IMAGES:
            step("receive", "Receive", False, f"send between 1 and {MAX_IMAGES} images")
            return finish("rejected", "wrong number of files")
        names = []
        for i, (name, data) in enumerate(uploads):
            target = incoming / f"{i:02d}_{_safe_name(name)}"
            target.write_bytes(data)
            names.append(target)
        total = sum(len(d) for _, d in uploads)
        TRAIL.record("file.receive", job=job, files=len(uploads), bytes=total)
        step("receive", "Receive", True, f"{len(uploads)} image(s), {total / 1e6:.2f} MB, held in VAJRA's work area")

        # 2. Image check, inside the jail ----------------------------------------
        image_reports = []
        cleaned: list[str] = []
        for i, src in enumerate(names):
            ext_out = clean / f"{i:02d}.img"
            rep = await asyncio.to_thread(_scan, ["image", str(src), "--clean-out", str(ext_out)])
            rep["name"] = uploads[i][0]
            image_reports.append(rep)
            if rep.get("safe"):
                final = ext_out.with_suffix(".png" if rep.get("clean_format") == "PNG" else ".jpg")
                ext_out.rename(final)
                cleaned.append(final.name)
        report["images"] = image_reports
        bad = [r for r in image_reports if not r.get("safe")]
        removed = sum(len(r.get("removed", [])) for r in image_reports)
        TRAIL.record("file.check", job=job, file="image", safe=not bad, removed=removed,
                     fingerprints=[r.get("fingerprint") for r in image_reports])
        if not step("image", "Check your image", not bad,
                    f"{len(bad)} image(s) failed the check" if bad else
                    f"well-formed; rebuilt from pixels only" + (f", {removed} metadata block(s) removed" if removed else "")):
            _burn_tree(folder)
            TRAIL.record("file.burn", job=job, stage="image", fingerprints=[r.get("fingerprint") for r in bad])
            return finish("burned", "the image itself failed the check, so it was never sent to the tool")
        for p in names:
            burn(p)  # the originals are no longer needed: only the rebuilt copies go to the tool

        # 3. Convert through the PDF tool, via VAJRA's MCP proxy -------------------
        if engine == "ilovepdf" and not ilovepdf_ready():
            step("convert", "Convert with iLovePDF", False, "ILOVEPDF_PUBLIC_KEY is not set in .env")
            _burn_tree(folder)
            return finish("error", "iLovePDF key missing")
        env = {"VAJRA_PDF_INCOMING": str(clean), "VAJRA_PDF_OUTPUT": str(quarantine)}
        if engine == "ilovepdf":
            env["ILOVEPDF_PUBLIC_KEY"] = os.environ["ILOVEPDF_PUBLIC_KEY"]
        cfg = {"pdf": UpstreamConfig("pdf", sys.executable, args=(PDF_SERVER,), env=env)}
        started = time.monotonic()
        async with UpstreamManager(cfg, trail=TRAIL, limits=TOOL_LIMITS) as ups:
            admissions = [{"tool": a.tool, "admitted": a.admitted, "reason": a.reason} for a in ups.admissions]
            up = ups.upstreams["pdf"]
            if "image_to_pdf" not in up.tools:
                step("convert", "Convert", False, "the tool was not admitted by the sandbox", admissions=admissions)
                _burn_tree(folder)
                return finish("burned", "tool rejected at admission")
            TRAIL.record("call", session=job, tool="pdf/image_to_pdf", arg_labels={"images": "trusted", "engine": "trusted"})
            result = await up.client.call_tool("image_to_pdf", {"images": cleaned, "engine": engine})
        if result.is_error:
            step("convert", "Convert", False, f"the tool reported an error: {_text(result)[:200]}", admissions=admissions)
            _burn_tree(folder)
            return finish("error", "conversion failed")
        info = json.loads(_text(result))
        report["conversion"] = info
        TRAIL.record("file.convert", job=job, converter=info.get("converter"), bytes=info.get("bytes"),
                     seconds=round(time.monotonic() - started, 1))
        step("convert", f"Convert with {info.get('converter')}", True,
             f"{info.get('bytes', 0) / 1e3:.0f} KB returned in {time.monotonic() - started:.1f}s; held in quarantine, marked untrusted",
             admissions=admissions, isolation=up.isolation)

        pdf = quarantine / info["file"]
        if tamper_with != "none":
            tamper(pdf, tamper_with)
            step("tamper", "Test: file changed in transit", True, TAMPER_TESTS[tamper_with], test=True)

        # 4. PDF scan, inside the jail --------------------------------------------
        scan = await asyncio.to_thread(_scan, ["pdf", str(pdf), "--expect-pages", str(len(cleaned))])
        report["scan"] = scan
        failed = [c for c in scan.get("checks", []) if not c["ok"]]
        TRAIL.record("file.check", job=job, file="pdf", safe=bool(scan.get("safe")), fingerprint=scan.get("fingerprint"),
                     failed=[c["name"] for c in failed])
        if not step("scan", "Sandbox scan", bool(scan.get("safe")),
                    f"{len(scan.get('checks', [])) - len(failed)} of {len(scan.get('checks', []))} checks passed"):
            _burn_tree(folder)
            TRAIL.record("file.burn", job=job, stage="pdf", fingerprint=scan.get("fingerprint"), failed=[c["name"] for c in failed])
            step("burn", "Burned in the sandbox", True, "overwritten and deleted; only its fingerprint is kept in the audit trail")
            return finish("burned", "; ".join(f"{c['name']}: {c['detail']}" for c in failed))

        # 5. Deliver ---------------------------------------------------------------
        token = secrets.token_hex(16)
        filename = (_safe_name(uploads[0][0]) if len(uploads) == 1 else "images") + ".pdf"
        shutil.move(pdf, DELIVERED / f"{token}.pdf")
        (DELIVERED / f"{token}.json").write_text(json.dumps({"filename": filename}), encoding="utf-8")
        _burn_tree(folder)
        TRAIL.record("file.deliver", job=job, fingerprint=scan.get("fingerprint"), bytes=scan.get("bytes"), pages=scan.get("pages"))
        step("deliver", "Delivered", True, f"{filename}, {scan.get('pages')} page(s), ready to download")
        report.update(download=f"/api/convert/file/{token}", filename=filename)
        return finish("delivered", "every check passed")
    except Exception as e:
        while isinstance(e, BaseExceptionGroup) and e.exceptions:
            e = e.exceptions[0]
        step("error", "Error", False, f"{type(e).__name__}: {str(e)[:200]}")
        if folder.exists():
            _burn_tree(folder)
        return finish("error", type(e).__name__)


def delivered_file(token: str) -> tuple[Path, str] | None:
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        return None
    pdf, meta = DELIVERED / f"{token}.pdf", DELIVERED / f"{token}.json"
    if not pdf.is_file():
        return None
    name = json.loads(meta.read_text(encoding="utf-8")).get("filename", "converted.pdf") if meta.is_file() else "converted.pdf"
    return pdf, name
