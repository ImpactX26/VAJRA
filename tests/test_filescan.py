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
