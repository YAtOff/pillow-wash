"""Slice 1: the core contract — a simple PNG comes back Clean.

Seam: the public `sanitize()` API (agreed interface), in-process mode.
"""

from __future__ import annotations

import io

from PIL import Image

from pillow_wash import Report, SanitizedImage, sanitize


def make_png(size=(8, 6), color=(200, 30, 40)) -> bytes:
    im = Image.new("RGB", size, color)
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def test_simple_png_comes_back_clean() -> None:
    src = make_png()

    result = sanitize(src, isolation="none")

    assert isinstance(result, SanitizedImage)
    assert isinstance(result.data, bytes)
    assert result.data[:8] == b"\x89PNG\r\n\x1a\n"

    out = Image.open(io.BytesIO(result.data))
    assert out.format == "PNG"
    assert out.size == (8, 6)


def test_report_describes_the_rebuild() -> None:
    src = make_png()

    result = sanitize(src, isolation="none")

    report = result.report
    assert isinstance(report, Report)
    assert report.input_format == "PNG"
    assert report.output_format == "PNG"
    assert report.width == 8
    assert report.height == 6
    assert report.frames == 1
    assert len(report.input_sha256) == 64
    assert len(report.output_sha256) == 64
    import hashlib
    assert report.input_sha256 == hashlib.sha256(src).hexdigest()
    assert report.output_sha256 == hashlib.sha256(result.data).hexdigest()


def test_visual_information_survives_bit_exact() -> None:
    src = make_png(size=(13, 7))

    result = sanitize(src, isolation="none")

    before = Image.open(io.BytesIO(src)).tobytes()
    after = Image.open(io.BytesIO(result.data)).tobytes()
    assert before == after
