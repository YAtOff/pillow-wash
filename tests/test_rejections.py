"""Slices 2-3: the Rejection taxonomy for inputs we refuse.

Seam: public `sanitize()` — every Rejection carries a branchable reason.
"""

from __future__ import annotations

import pytest

from image_sanitizer import (
    RejectionError,
    RejectionReason,
    Undecodable,
    UnsupportedFormat,
    sanitize,
)

SVG = b"""<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">
  <script>alert(1)</script><rect width="10" height="10"/>
</svg>"""

HEIC = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 64

TIFF = b"II*\x00\x08\x00\x00\x00" + b"\x00" * 32


@pytest.mark.parametrize(
    ("payload", "name"),
    [
        (SVG, "SVG"),
        (HEIC, "HEIC"),
        (TIFF, "TIFF"),
    ],
)
def test_known_unsupported_formats_are_rejected(payload: bytes, name: str) -> None:
    with pytest.raises(UnsupportedFormat) as ei:
        sanitize(payload, isolation="none")
    assert ei.value.reason is RejectionReason.UNSUPPORTED_FORMAT
    assert name.lower() in ei.value.detail.lower()
    assert isinstance(ei.value, RejectionError)


def test_random_bytes_are_unrecognized() -> None:
    with pytest.raises(UnsupportedFormat) as ei:
        sanitize(b"not an image at all, just text", isolation="none")
    assert ei.value.reason is RejectionReason.UNSUPPORTED_FORMAT
    assert "unrecognized" in ei.value.detail


def test_empty_input_is_rejected() -> None:
    with pytest.raises(UnsupportedFormat):
        sanitize(b"", isolation="none")


def test_corrupt_png_is_undecodable() -> None:
    bad = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64  # magic + junk
    with pytest.raises(Undecodable) as ei:
        sanitize(bad, isolation="none")
    assert ei.value.reason is RejectionReason.UNDECODABLE


def test_truncated_jpeg_is_undecodable() -> None:
    bad = b"\xff\xd8\xff\xe0" + b"\x00" * 16  # SOI + APP0 stub, cut short
    with pytest.raises(Undecodable) as ei:
        sanitize(bad, isolation="none")
    assert ei.value.reason is RejectionReason.UNDECODABLE


def test_bmp_magic_with_garbage_is_undecodable() -> None:
    bad = b"BM" + b"\x00" * 62  # supported magic, no real bitmap
    with pytest.raises(Undecodable) as ei:
        sanitize(bad, isolation="none")
    assert ei.value.reason is RejectionReason.UNDECODABLE
