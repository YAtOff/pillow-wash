"""Slice 7: ICC profiles — validated pass-through, never blind copy.

Seam: public `sanitize()`; output inspected by independent Pillow parse.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image, ImageCms

from image_sanitizer import Limits, MetadataInvalid, RejectionReason, sanitize

from imgfactory import make_jpeg, make_png


def srgb_profile() -> bytes:
    return ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()


def test_jpeg_icc_passes_through_validated() -> None:
    prof = srgb_profile()
    src = make_jpeg(icc_profile=prof)

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    assert out.info.get("icc_profile") == prof
    assert b"ICC_PROFILE\x00" in result.data  # really carried in APP2
    assert any(a.kind == "kept" and "ICC" in a.detail for a in result.report.actions)


def test_png_icc_passes_through_validated() -> None:
    prof = srgb_profile()
    src = make_png()
    im = Image.open(io.BytesIO(src))
    buf = io.BytesIO()
    im.save(buf, "PNG", icc_profile=prof)
    src = buf.getvalue()

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    assert out.info.get("icc_profile") == prof


def test_oversized_icc_is_rejected() -> None:
    prof = srgb_profile() + b"\x00" * (1024 * 1024)  # > 1 MiB cap
    src = make_jpeg(icc_profile=prof)

    with pytest.raises(MetadataInvalid) as ei:
        sanitize(src, isolation="none")
    assert ei.value.reason is RejectionReason.METADATA_INVALID
    assert "icc_max_bytes" in ei.value.detail


def test_corrupt_icc_is_rejected() -> None:
    src = make_jpeg(icc_profile=b"JUNKJUNKJUNKJUNK" * 4)

    with pytest.raises(MetadataInvalid) as ei:
        sanitize(src, isolation="none")
    assert ei.value.reason is RejectionReason.METADATA_INVALID
    assert "validation" in ei.value.detail.lower() or "profile" in ei.value.detail.lower()


def test_icc_size_cap_is_configurable() -> None:
    prof = srgb_profile() + b"\x00" * (1024 * 1024 + 100)  # over the 1 MiB default
    src = make_jpeg(icc_profile=prof)
    with pytest.raises(MetadataInvalid):
        sanitize(src, isolation="none")
    result = sanitize(
        src, limits=Limits(icc_max_bytes=len(prof) + 1), isolation="none"
    )
    assert Image.open(io.BytesIO(result.data)).info.get("icc_profile") == prof
