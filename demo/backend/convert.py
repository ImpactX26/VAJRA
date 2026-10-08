"""Secure convert: PDF tasks through a real third-party tool (iLovePDF), with VAJRA in between.

    user files -> input check (jailed) -> pdf tool via MCP (jailed, admitted)
               -> quarantine -> PDF scan (jailed) -> burn | deliver to the user's device

Operations: "imagepdf" (images to one PDF; images are rebuilt from pixels first) and
"merge" (two or more PDFs into one; the result must contain exactly the inputs' text).

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
OPERATIONS = {
    "imagepdf": {"title": "Image to PDF", "tool": "image_to_pdf", "arg": "images", "min": 1, "noun": "image"},
    "merge": {"title": "Merge PDFs", "tool": "merge_pdfs", "arg": "files", "min": 2, "noun": "PDF"},
}

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
        if "/Resources" not in page:
            page[NameObject("/Resources")] = DictionaryObject()
        resources = page["/Resources"].get_object()
        fonts = resources.get("/Font")
        fonts = fonts.get_object() if fonts is not None else DictionaryObject()
        fonts[NameObject("/FVajraTest")] = writer._add_object(font)
        resources[NameObject("/Font")] = fonts
        text = DecodedStreamObject()
        text.set_data(b"BT /FVajraTest 1 Tf 3 Tr 5 5 Td (VAJRA test marker: text that is not in your file) Tj ET")  # 3 Tr = invisible
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


async def convert(uploads: list[tuple[str, bytes]], engine: str, tamper_with: str, operation: str = "imagepdf") -> dict[str, Any]:
    op = OPERATIONS[operation]
    cleanup_old()
    job = secrets.token_hex(6)
    folder = WORK / job
    incoming, clean, quarantine = folder / "incoming", folder / "clean", folder / "quarantine"
    for d in (incoming, clean, quarantine, DELIVERED):
        d.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []
    report: dict[str, Any] = {"job": job, "operation": operation, "engine": engine, "tamper": tamper_with, "steps": steps}

    def step(sid: str, title: str, ok: bool, detail: str, **extra: Any) -> bool:
        steps.append({"id": sid, "title": title, "ok": ok, "detail": detail, **extra})
        return ok

    def finish(verdict: str, reason: str) -> dict[str, Any]:
        report.update(verdict=verdict, reason=reason)
        TRAIL.record("file.verdict", job=job, verdict=verdict, reason=reason)
        return report

    try:
        # 1. Receive -----------------------------------------------------------
        if not op["min"] <= len(uploads) <= MAX_IMAGES:
            step("receive", "Receive", False, f"send between {op['min']} and {MAX_IMAGES} {op['noun']} files")
            return finish("rejected", "wrong number of files")
        names = []
        for i, (name, data) in enumerate(uploads):
            target = incoming / f"{i:02d}_{_safe_name(name)}"
            target.write_bytes(data)
            names.append(target)
        total = sum(len(d) for _, d in uploads)
        TRAIL.record("file.receive", job=job, operation=operation, files=len(uploads), bytes=total)
        step("receive", "Receive", True, f"{len(uploads)} {op['noun']}(s), {total / 1e6:.2f} MB, held in VAJRA's work area")

        # 2. Input check, inside the jail ----------------------------------------
        if operation == "merge":
            pdf_reports = []
            for i, src in enumerate(names):
                rep = await asyncio.to_thread(_scan, ["pdf", str(src), "--profile", "document"])
                rep["name"] = uploads[i][0]
                pdf_reports.append(rep)
            report["inputs"] = pdf_reports
            bad = [r for r in pdf_reports if not r.get("safe")]
            TRAIL.record("file.check", job=job, file="input pdf", safe=not bad,
                         fingerprints=[r.get("fingerprint") for r in pdf_reports])
            pages_in = sum(r.get("pages", 0) for r in pdf_reports)
            if not step("image", "Check your PDFs", not bad,
                        f"{len(bad)} of {len(names)} PDF(s) failed the check" if bad else
                        f"{len(names)} PDFs, {pages_in} page(s): no scripts, actions, attachments or invisible text"):
                _burn_tree(folder)
                TRAIL.record("file.burn", job=job, stage="input", fingerprints=[r.get("fingerprint") for r in bad])
                step("burn", "Burned in the sandbox", True, "the unsafe PDF was never sent to the tool; overwritten and deleted")
                return finish("burned", "; ".join(f"{r['name']}: " + ", ".join(c["name"] for c in r["checks"] if not c["ok"]) for r in bad))
            cleaned = []
            for i, src in enumerate(names):
                target = clean / f"{i + 1:02d}_{_safe_name(uploads[i][0])}.pdf"
                src.rename(target)
                cleaned.append(target.name)
            expected_text = [fp for r in pdf_reports for fp in r.get("page_text", [])]
        else:
            cleaned = await _check_images(job, names, uploads, clean, report, step)
            pages_in = len(cleaned or [])
            if cleaned is None:
                _burn_tree(folder)
                step("burn", "Burned in the sandbox", True, "the unsafe image was never sent to the tool; overwritten and deleted")
                return finish("burned", "the image itself failed the check, so it was never sent to the tool")

        # 3. Run the PDF tool, via VAJRA's MCP proxy -------------------------------
        if engine == "ilovepdf" and not ilovepdf_ready():
            step("convert", "iLovePDF", False, "ILOVEPDF_PUBLIC_KEY is not set in .env")
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
            if op["tool"] not in up.tools:
                step("convert", "PDF tool", False, "the tool was not admitted by the sandbox", admissions=admissions)
                _burn_tree(folder)
                return finish("burned", "tool rejected at admission")
            TRAIL.record("call", session=job, tool=f"pdf/{op['tool']}", arg_labels={op["arg"]: "trusted", "engine": "trusted"})
            result = await up.client.call_tool(op["tool"], {op["arg"]: cleaned, "engine": engine})
        if result.is_error:
            step("convert", "PDF tool", False, f"the tool reported an error: {_text(result)[:200]}", admissions=admissions)
            _burn_tree(folder)
            return finish("error", "the tool failed")
        info = json.loads(_text(result))
        report["conversion"] = info
        TRAIL.record("file.convert", job=job, operation=operation, converter=info.get("converter"), bytes=info.get("bytes"),
                     seconds=round(time.monotonic() - started, 1))
        verb = "Merge" if operation == "merge" else "Convert"
        step("convert", f"{verb} with {info.get('converter')}", True,
             f"{info.get('bytes', 0) / 1e3:.0f} KB returned in {time.monotonic() - started:.1f}s; held in quarantine, marked untrusted",
             admissions=admissions, isolation=up.isolation)

        pdf = quarantine / info["file"]
        if tamper_with != "none":
            tamper(pdf, tamper_with)
            step("tamper", "Test: file changed in transit", True, TAMPER_TESTS[tamper_with], test=True)

        # 4. PDF scan, inside the jail --------------------------------------------
        profile = "document" if operation == "merge" else "images"
        scan = await asyncio.to_thread(_scan, ["pdf", str(pdf), "--profile", profile, "--expect-pages", str(pages_in)])
        if operation == "merge" and "page_text" in scan:
            # The tool may only rearrange what it was given: every page's text must match an input page, in order.
            same = scan["page_text"] == expected_text
            changed = sum(a != b for a, b in zip(scan["page_text"], expected_text)) + abs(len(scan["page_text"]) - len(expected_text))
            scan["checks"].append({"name": "Same content as your files", "ok": same,
                                   "detail": "every page's text matches your PDFs" if same else f"{changed} page(s) differ from your PDFs"})
            scan["safe"] = bool(scan.get("safe")) and same
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
        filename = "merged.pdf" if operation == "merge" else (_safe_name(uploads[0][0]) if len(uploads) == 1 else "images") + ".pdf"
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


async def _check_images(job: str, names: list[Path], uploads: list[tuple[str, bytes]], clean: Path,
                        report: dict[str, Any], step: Any) -> list[str] | None:
    """Check each image in the jail and rebuild it from pixels. Returns the rebuilt file names, or None if any failed."""
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
                "well-formed; rebuilt from pixels only" + (f", {removed} metadata block(s) removed" if removed else "")):
        TRAIL.record("file.burn", job=job, stage="image", fingerprints=[r.get("fingerprint") for r in bad])
        return None
    for p in names:
        burn(p)  # the originals are no longer needed: only the rebuilt copies go to the tool
    return cleaned


def delivered_file(token: str) -> tuple[Path, str] | None:
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        return None
    pdf, meta = DELIVERED / f"{token}.pdf", DELIVERED / f"{token}.json"
    if not pdf.is_file():
        return None
    name = json.loads(meta.read_text(encoding="utf-8")).get("filename", "converted.pdf") if meta.is_file() else "converted.pdf"
    return pdf, name


# --------------------------------------------------------------------------- download guard
# Used by the browser extension: one file the user is downloading, checked before it reaches the disk.

PDF_MAGIC = b"%PDF-"
IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"RIFF")


def guard_kind(name: str, data: bytes) -> str:
    """What the bytes are (by content, not by name)."""
    head = data[:16]
    if head.startswith(PDF_MAGIC):
        return "pdf"
    if any(head.startswith(m) for m in IMAGE_MAGIC):
        return "image"
    lower = name.lower()
    if lower.endswith(".pdf"):
        return "pdf"  # claims to be a PDF but is not one: the scan will say so
    if lower.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return "image"
    return "other"


async def guard(name: str, data: bytes, source: str) -> dict[str, Any]:
    """Check one downloaded file in the jailed sandbox. Safe files are delivered (images rebuilt
    from pixels first); unsafe files are burned. Other file types are not handled here."""
    cleanup_old()
    job = secrets.token_hex(6)
    folder = WORK / job
    folder.mkdir(parents=True, exist_ok=True)
    DELIVERED.mkdir(parents=True, exist_ok=True)
    kind = guard_kind(name, data)
    filename = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).name)[:80] or "download"
    report: dict[str, Any] = {"job": job, "kind": kind, "name": filename, "source": source, "bytes": len(data)}
    TRAIL.record("guard.receive", job=job, source=source, type=kind, bytes=len(data))
    try:
        if kind == "other":
            report.update(verdict="skipped", reason="not a PDF or image; VAJRA Download Guard only checks those")
            return report
        if len(data) > MAX_UPLOAD:
            report.update(verdict="burned", reason=f"larger than {MAX_UPLOAD // 2**20} MB", checks=[])
            TRAIL.record("file.burn", job=job, stage="guard", reason="size")
            return report
        src = folder / ("in.pdf" if kind == "pdf" else "in.img")
        src.write_bytes(data)
        out = folder / "clean.img"
        args = ["pdf", str(src), "--profile", "document"] if kind == "pdf" else ["image", str(src), "--clean-out", str(out)]
        scan = await asyncio.to_thread(_scan, args)
        failed = [c for c in scan.get("checks", []) if not c["ok"]]
        report.update(checks=scan.get("checks", []), removed=scan.get("removed", []), notes=scan.get("notes", []),
                      fingerprint=scan.get("fingerprint"))
        TRAIL.record("file.check", job=job, file=f"download {kind}", safe=bool(scan.get("safe")),
                     fingerprint=scan.get("fingerprint"), failed=[c["name"] for c in failed])
        if not scan.get("safe"):
            TRAIL.record("file.burn", job=job, stage="guard", fingerprint=scan.get("fingerprint"), failed=[c["name"] for c in failed])
            report.update(verdict="burned", reason="; ".join(f"{c['name']}: {c['detail']}" for c in failed))
            return report
        token = secrets.token_hex(16)
        if kind == "image":
            ext = ".png" if scan.get("clean_format") == "PNG" else ".jpg"
            filename = Path(filename).stem + ext
            shutil.move(out, DELIVERED / f"{token}.pdf")  # stored under the token; served with the real name
        else:
            shutil.move(src, DELIVERED / f"{token}.pdf")
        (DELIVERED / f"{token}.json").write_text(json.dumps({"filename": filename}), encoding="utf-8")
        TRAIL.record("file.deliver", job=job, fingerprint=scan.get("fingerprint"), bytes=len(data), source=source)
        report.update(verdict="delivered", reason="every check passed", filename=filename,
                      download=f"/api/convert/file/{token}")
        return report
    finally:
        if folder.exists():
            _burn_tree(folder)
