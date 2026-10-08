"""The file sandbox passes clean conversions and burns anything that is not pictures only."""

import io
from pathlib import Path

import pytest

pytest.importorskip("pypdf")
from PIL import Image  # noqa: E402

from demo.backend.convert import TAMPER_TESTS, convert, tamper  # noqa: E402
from vajra.filescan import scan_image, scan_pdf  # noqa: E402


def _jpeg() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (320, 240), "#2563eb").save(buf, "JPEG")
    return buf.getvalue()


def _pdf(tmp_path: Path) -> Path:
    out = tmp_path / "doc.pdf"
    Image.new("RGB", (320, 240), "#2563eb").save(out, "PDF")
    return out


def test_clean_pdf_passes(tmp_path):
    report = scan_pdf(_pdf(tmp_path), expect_pages=1)
    assert report["safe"], report["checks"]


@pytest.mark.parametrize("how", [t for t in TAMPER_TESTS if t != "none"])
def test_every_tampering_is_caught(tmp_path, how):
    pdf = _pdf(tmp_path)
    tamper(pdf, how)
    report = scan_pdf(pdf, expect_pages=1)
    assert not report["safe"]


def test_page_count_must_match(tmp_path):
    assert not scan_pdf(_pdf(tmp_path), expect_pages=2)["safe"]


def test_image_with_hidden_trailing_data_is_rejected(tmp_path):
    src = tmp_path / "in.jpg"
    src.write_bytes(_jpeg() + b"x" * 400)
    assert not scan_image(src, tmp_path / "clean.jpg")["safe"]


def test_image_metadata_is_stripped(tmp_path):
    src = tmp_path / "in.jpg"
    exif = Image.Exif()
    exif[0x010E] = "description field"  # ImageDescription
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), "red").save(buf, "JPEG", exif=exif)
    src.write_bytes(buf.getvalue())
    report = scan_image(src, tmp_path / "clean.jpg")
    assert report["safe"] and report["removed"]
    with Image.open(tmp_path / "clean.jpg") as cleaned:
        assert len(cleaned.getexif()) == 0


async def test_pipeline_delivers_clean_and_burns_tampered():
    ok = await convert([("photo.jpg", _jpeg())], "offline", "none")
    assert ok["verdict"] == "delivered" and ok["download"]
    bad = await convert([("photo.jpg", _jpeg())], "offline", "script")
    assert bad["verdict"] == "burned" and "download" not in bad
    assert [s["id"] for s in bad["steps"]][-1] == "burn"


def text_pdf(lines: list[str]) -> bytes:
    """A small ordinary PDF with one line of visible text per page."""
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    w = PdfWriter()
    for line in lines:
        page = w.add_blank_page(300, 200)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): w._add_object(font)})})
        stream = DecodedStreamObject()
        stream.set_data(b"BT /F1 12 Tf 20 100 Td (" + line.encode() + b") Tj ET")
        page[NameObject("/Contents")] = w._add_object(stream)
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def test_document_profile_allows_visible_text_but_not_invisible(tmp_path):
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(text_pdf(["Quarterly report", "Page two"]))
    assert scan_pdf(doc, 2, "document")["safe"]
    tamper(doc, "hidden_text")
    report = scan_pdf(doc, 2, "document")
    assert not report["safe"] and any(c["name"] == "No invisible text" and not c["ok"] for c in report["checks"])


async def test_merge_delivers_clean_and_burns_tampered_or_unsafe_inputs(tmp_path):
    a, b = text_pdf(["First file"]), text_pdf(["Second file", "Second file page two"])
    ok = await convert([("a.pdf", a), ("b.pdf", b)], "offline", "none", "merge")
    assert ok["verdict"] == "delivered", ok["steps"]
    assert any(c["name"] == "Same content as your files" and c["ok"] for c in ok["scan"]["checks"])

    bad = await convert([("a.pdf", a), ("b.pdf", b)], "offline", "hidden_text", "merge")
    assert bad["verdict"] == "burned"

    scripted = tmp_path / "s.pdf"
    scripted.write_bytes(a)
    tamper(scripted, "script")
    early = await convert([("s.pdf", scripted.read_bytes()), ("b.pdf", b)], "offline", "none", "merge")
    assert early["verdict"] == "burned" and "convert" not in [s["id"] for s in early["steps"]]


def test_damage_found_while_reading_pages_is_caught(tmp_path):
    # A page whose content is not a stream: opening the file succeeds, reading the page reveals the damage.
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject

    w = PdfWriter()
    page = w.add_blank_page(300, 200)
    page[NameObject("/Contents")] = w._add_object(DictionaryObject())
    doc = tmp_path / "damaged.pdf"
    with doc.open("wb") as f:
        w.write(f)
    report = scan_pdf(doc, 1, "document")
    assert not report["safe"]
    assert any(c["name"] == "Readable structure" and not c["ok"] for c in report["checks"])
