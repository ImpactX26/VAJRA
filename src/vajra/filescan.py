"""File sandbox: structural inspection of files that arrive from a tool, before a person receives them.

Run as a standalone script inside VAJRA's OS jail, so a file crafted to crash or exploit
the parser takes down only the jailed process:

    python filescan.py image <in> --clean-out <out>     # check an image and re-encode it without metadata
    python filescan.py pdf <in> --expect-pages N        # check a PDF produced from N images

It prints one JSON report on stdout. Like the rest of VAJRA, it never judges what text
*means*: it checks what a file is made of against what that kind of file should contain.
Any content that is removed or rejected is reported by kind, size and fingerprint only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

MAX_BYTES = 40 * 1024 * 1024
MAX_PIXELS = 60_000_000

# PDF names that make a document *do* something, hide something, or hide from inspection.
ACTIVE_NAMES = {
    "/JavaScript": "embedded script",
    "/JS": "embedded script",
    "/Launch": "action that starts a program",
    "/EmbeddedFile": "hidden attached file",
    "/EmbeddedFiles": "hidden attached file",
    "/SubmitForm": "action that sends data to a server",
    "/ImportData": "action that loads outside data",
    "/GoToR": "action that opens another file",
    "/GoToE": "action that opens an embedded file",
    "/URI": "web link",
    "/RichMedia": "embedded media player",
    "/XFA": "dynamic form",
    "/AcroForm": "interactive form",
    "/AA": "action that runs automatically",
    "/Encrypt": "encrypted content that cannot be inspected",
    "/JBIG2Decode": "image codec with a history of exploits",
    "/Movie": "embedded media",
    "/Sound": "embedded media",
}
NAME_RE = re.compile(rb"/[A-Za-z0-9#._-]+")


def fingerprint(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()[:32]


def _decode_name(raw: bytes) -> str:
    # PDF names may hide letters as #xx escapes ("/J#61vaScript"); decode before comparing.
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw).decode("latin-1")


class Report:
    def __init__(self, kind: str, data: bytes) -> None:
        self.out: dict[str, Any] = {"kind": kind, "bytes": len(data), "fingerprint": fingerprint(data), "checks": [], "removed": []}

    def check(self, name: str, ok: bool, detail: str) -> bool:
        self.out["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    def removed(self, kind: str, size: int) -> None:
        self.out["removed"].append({"kind": kind, "size": size})

    def finish(self, **extra: Any) -> dict[str, Any]:
        self.out.update(extra)
        self.out["safe"] = all(c["ok"] for c in self.out["checks"])
        return self.out


# --------------------------------------------------------------------------- images

def _image_end(data: bytes, fmt: str) -> int | None:
    """Offset where the image format says the file ends (anything after it is smuggled data)."""
    if fmt == "PNG":
        i = data.rfind(b"IEND")
        return i + 8 if i >= 0 else None  # chunk type + CRC
    if fmt == "JPEG":
        i = data.rfind(b"\xff\xd9")
        return i + 2 if i >= 0 else None
    return None


def scan_image(path: Path, clean_out: Path) -> dict[str, Any]:
    from PIL import Image, ImageOps

    Image.MAX_IMAGE_PIXELS = MAX_PIXELS
    data = path.read_bytes()
    r = Report("image", data)
    if not r.check("Size limit", len(data) <= MAX_BYTES, f"{len(data) / 1e6:.1f} MB"):
        return r.finish()

    try:
        with Image.open(path) as probe:
            fmt = probe.format or "unknown"
            probe.verify()  # structural check of the whole file, without keeping pixels
    except Exception as e:  # any decoder complaint means the file is not a well-formed image
        r.check("Well-formed image", False, f"decoder refused it ({type(e).__name__})")
        return r.finish()
    if not r.check("Allowed format", fmt in ("PNG", "JPEG", "WEBP"), fmt):
        return r.finish(format=fmt)
    r.check("Well-formed image", True, f"{fmt} decoded without errors")

    end = _image_end(data, fmt)
    trailing = len(data) - end if end is not None else 0
    r.check("Nothing hidden after the image", trailing <= 16,
            "no extra data" if trailing <= 16 else f"{trailing} bytes of extra data after the image ends")

    with Image.open(path) as img:
        info_keys = [k for k in img.info if k not in ("dpi", "gamma", "transparency", "srgb", "icc_profile")]
        meta = {
            "camera and location data (EXIF)": len(img.getexif()) > 0,
            "text or comment fields": any(isinstance(img.info.get(k), (str, bytes)) for k in info_keys),
            "XMP metadata": "xmp" in img.info or "XML:com.adobe.xmp" in img.info,
        }
        img = ImageOps.exif_transpose(img)  # keep the photo the right way up once EXIF is gone
        if not r.check("Image size", img.width * img.height <= MAX_PIXELS, f"{img.width} x {img.height}"):
            return r.finish(format=fmt)
        rgb = img.convert("RGBA" if img.mode in ("RGBA", "LA", "P") else "RGB")
        # Rebuild the file from pixels only: metadata, extra chunks and trailing data cannot survive this.
        if rgb.mode == "RGBA":
            rgb.save(clean_out, "PNG", optimize=True)
        else:
            rgb.save(clean_out, "JPEG", quality=95)
    for kind, present in meta.items():
        if present:
            r.removed(kind, 0)
    return r.finish(format=fmt, width=rgb.width, height=rgb.height, clean_format="PNG" if rgb.mode == "RGBA" else "JPEG")


# --------------------------------------------------------------------------- PDFs

def _walk(obj: Any, seen: set[int], found: dict[str, int], depth: int = 0) -> None:
    """Visit every object reachable from the document, following references (incl. object streams)."""
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

    if depth > 200:
        return
    if isinstance(obj, IndirectObject):
        if obj.idnum in seen:
            return
        seen.add(obj.idnum)
        obj = obj.get_object()
    if isinstance(obj, DictionaryObject):
        for key, value in obj.items():
            name = str(key)
            if name == "/OpenAction":
                target = value.get_object()
                if isinstance(target, DictionaryObject) and "/S" in target:  # an action, not just a page to show
                    found["action that runs when the file opens"] = found.get("action that runs when the file opens", 0) + 1
            elif name in ACTIVE_NAMES:
                found[ACTIVE_NAMES[name]] = found.get(ACTIVE_NAMES[name], 0) + 1
            if name == "/S" and str(value) in ACTIVE_NAMES:
                found[ACTIVE_NAMES[str(value)]] = found.get(ACTIVE_NAMES[str(value)], 0) + 1
            if name != "/Parent":
                _walk(value, seen, found, depth + 1)
    elif isinstance(obj, ArrayObject):
        for item in obj:
            _walk(item, seen, found, depth + 1)


def _page_text_ops(page: Any) -> int:
    """Number of text-drawing operators on a page. A PDF made from images should have none."""
    contents = page.get_contents()
    if contents is None:
        return 0
    raw = contents.get_data()
    return len(re.findall(rb"(?<![A-Za-z])(Tj|TJ|'|\")(?![A-Za-z])", raw)) + len(re.findall(rb"(?<![A-Za-z])BT(?![A-Za-z])", raw))


def scan_pdf(path: Path, expect_pages: int | None) -> dict[str, Any]:
    from pypdf import PdfReader

    data = path.read_bytes()
    r = Report("pdf", data)
    if not r.check("Size limit", len(data) <= MAX_BYTES, f"{len(data) / 1e6:.1f} MB"):
        return r.finish()
    r.check("Starts as a PDF", data.startswith(b"%PDF-"), data[:8].decode("latin-1", "replace").strip() or "empty file")

    eof = data.rfind(b"%%EOF")
    trailing = len(data) - (eof + 5) if eof >= 0 else len(data)
    r.check("Nothing hidden after the end of the file", eof >= 0 and len(data[eof + 5:].strip()) == 0,
            "clean ending" if eof >= 0 and not data[eof + 5:].strip() else f"{trailing} bytes after the end marker")

    raw_names = {ACTIVE_NAMES[n] for n in map(_decode_name, NAME_RE.findall(data)) if n in ACTIVE_NAMES}

    warnings: list[str] = []
    handler = logging.Handler()
    handler.emit = lambda rec: warnings.append(rec.getMessage())  # type: ignore[method-assign]
    logging.getLogger("pypdf").addHandler(handler)
    try:
        reader = PdfReader(path, strict=True)
        if reader.is_encrypted:
            r.check("Readable structure", False, "file is encrypted, so it cannot be inspected")
            return r.finish()
        pages = list(reader.pages)
        found: dict[str, int] = {}
        _walk(reader.trailer, set(), found)
    except Exception as e:  # strict parsing: any structural error is a failure, not something to repair
        r.check("Readable structure", False, f"parser error ({type(e).__name__})")
        return r.finish()
    r.check("Readable structure", not warnings, "no parser errors or repairs" if not warnings else f"{len(warnings)} parser warning(s)")

    for kind in sorted(raw_names):
        found.setdefault(kind, 1)
    r.check("No active content", not found,
            "no scripts, actions, links, forms or attachments" if not found else "; ".join(f"{k} ({n})" for k, n in sorted(found.items())))

    if expect_pages is not None:
        r.check("One page per image", len(pages) == expect_pages, f"{len(pages)} page(s), expected {expect_pages}")

    text_ops = sum(_page_text_ops(p) for p in pages)
    fonts = sum(1 for p in pages if "/Font" in (p.get("/Resources") or {}))
    extracted = sum(len((p.extract_text() or "").strip()) for p in pages)
    # A PDF converted from pictures holds pictures only. Text here was not in the user's image:
    # it is the classic hiding place for instructions aimed at AI tools that read the file later.
    r.check("Pictures only, no text layer", text_ops == 0 and fonts == 0 and extracted == 0,
            "pages contain images only" if text_ops == fonts == extracted == 0
            else f"text layer found: {extracted} characters, {text_ops} text operator(s), {fonts} font(s)")
    if extracted:
        r.removed("text layer not present in the source image", extracted)

    images = 0
    others: set[str] = set()
    for p in pages:
        xobjects = (p.get("/Resources") or {}).get("/XObject") or {}
        for ref in xobjects.values():
            subtype = str(ref.get_object().get("/Subtype"))
            images += subtype == "/Image"
            if subtype != "/Image":
                others.add(subtype)
    annots = sum(len(p.get("/Annots") or []) for p in pages)
    r.check("Only images and no overlays", images >= len(pages) and not others and annots == 0,
            f"{images} image(s)" + (f", other objects: {', '.join(sorted(others))}" if others else "")
            + (f", {annots} annotation(s)" if annots else ""))
    return r.finish(pages=len(pages))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="filescan")
    sub = p.add_subparsers(dest="mode", required=True)
    im = sub.add_parser("image")
    im.add_argument("path", type=Path)
    im.add_argument("--clean-out", type=Path, required=True)
    pdf = sub.add_parser("pdf")
    pdf.add_argument("path", type=Path)
    pdf.add_argument("--expect-pages", type=int)
    a = p.parse_args(argv)
    try:
        report = scan_image(a.path, a.clean_out) if a.mode == "image" else scan_pdf(a.path, a.expect_pages)
    except Exception as e:  # never crash silently: an unscannable file is an unsafe file
        report = {"kind": a.mode, "safe": False, "checks": [{"name": "Scanner", "ok": False, "detail": type(e).__name__}], "removed": []}
    json.dump(report, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
