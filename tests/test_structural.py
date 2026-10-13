"""Slice 8: structural attacks — second images, trailers, XMP, IFD1 thumbs.

Everything here must be gone from Clean output *by construction* (the
rebuild emits only what we wrote), not by detection.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image

from pillow_wash import sanitize

from imgfactory import make_jpeg


def one_soi_count(data: bytes) -> int:
    return data.count(b"\xff\xd8")


def test_mpo_style_concat_keeps_only_first_image() -> None:
    first = make_jpeg(size=(4, 4))
    second = make_jpeg(size=(6, 2), color=(9, 9, 9))
    src = first + second  # MPO-ish: second JPEG appended

    result = sanitize(src, isolation="none")

    assert result.data.endswith(b"\xff\xd9")
    assert one_soi_count(result.data) == 1  # second SOI gone
    out = Image.open(io.BytesIO(result.data))
    assert out.size == (4, 4)


def test_payload_after_eoi_is_dropped() -> None:
    src = make_jpeg() + b"<?php system($_GET['c']); ?>"

    result = sanitize(src, isolation="none")

    assert result.data.endswith(b"\xff\xd9")
    assert b"<?php" not in result.data


def test_xmp_packet_is_dropped() -> None:
    xmp = b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>evil</rdf:RDF></x:xmpmeta>'
    src = make_jpeg(xmp=xmp)
    assert b"adobe:ns" in src

    result = sanitize(src, isolation="none")

    assert b"adobe:ns" not in result.data
    assert b"<rdf" not in result.data


def test_ifd1_thumbnail_never_survives() -> None:
    ex = Image.Exif()
    ex[306] = "2023:01:02 03:04:05"
    ifd1 = ex.get_ifd(1)
    ifd1[513] = 0  # JPEGInterchangeFormat
    ifd1[514] = 4  # ...FormatLength — claims an embedded second JPEG
    src = make_jpeg(exif=ex.tobytes())

    result = sanitize(src, isolation="none")

    out_ex = Image.open(io.BytesIO(result.data)).getexif()
    assert dict(out_ex.get_ifd(1)) == {}
    assert out_ex.get(306) == "2023:01:02 03:04:05"  # whitelist item still kept


def test_leading_junk_before_png_magic_is_rejected() -> None:
    from imgfactory import make_png

    src = b"JUNK" + make_png()
    with pytest.raises(Exception) as ei:
        sanitize(src, isolation="none")
    from pillow_wash import UnsupportedFormat

    assert isinstance(ei.value, UnsupportedFormat)
