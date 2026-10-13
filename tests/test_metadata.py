"""Slice 5: the Metadata Whitelist — what survives and what never rides along.

Seam: public `sanitize()`. Assertions inspect the *output bytes* (parsed
independently), never our internal objects.
"""

from __future__ import annotations

import io
import re

import pytest
from PIL import Image

from image_sanitizer import MetadataInvalid, RejectionReason, sanitize

from imgfactory import make_jpeg, make_png, png_chunks, png_insert_chunk

TS = "2023:01:02 03:04:05"
TS2 = "2023:01:02 03:04:06"
TS_RE = re.compile(r"^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$")


def build_exif(software="EvilSoft 1.0", user_comment="payload", gps=True,
               dto=TS2, dt=TS) -> bytes:
    ex = Image.Exif()
    if dt:
        ex[306] = dt
    if software:
        ex[305] = software
    sub = ex.get_ifd(0x8769)
    if dto:
        sub[36867] = dto
    if user_comment:
        sub[37510] = user_comment
    if gps:
        g = ex.get_ifd(0x8825)
        g[1] = "N"
        g[2] = (42.0, 0.0, 0.0)
    return ex.tobytes()


# ------------------------------------------------------------------ PNG ----

def test_png_text_chunks_are_dropped() -> None:
    src = make_png()
    src = png_insert_chunk(src, b"tEXt", b"Comment\x00<script>alert(1)</script>")
    src = png_insert_chunk(src, b"iTXt", b"Title\x00\x00\x00\x00\x00evil")

    result = sanitize(src, isolation="none")

    types = [t for t, _ in png_chunks(result.data)]
    assert b"tEXt" not in types
    assert b"iTXt" not in types
    assert b"<script>" not in result.data
    assert any(a.kind == "dropped" for a in result.report.actions)


def test_raw_profile_smuggling_chunk_is_dropped() -> None:
    payload = b"Raw profile type exif\x00" + b"\nexif\n00000042: 4d4d..." * 4
    src = png_insert_chunk(make_png(), b"zTXt", payload[:2] + b"\x00\x00" + payload[2:])

    result = sanitize(src, isolation="none")

    types = [t for t, _ in png_chunks(result.data)]
    assert b"zTXt" not in types


def test_post_iend_webshell_trailer_is_dropped() -> None:
    src = make_png() + b"<?php system($_GET['c']); ?>"
    assert src.endswith(b"<?php system($_GET['c']); ?>")

    result = sanitize(src, isolation="none")

    assert b"<?php" not in result.data
    assert [t for t, _ in png_chunks(result.data)][-1] == b"IEND"


# ----------------------------------------------------------------- JPEG ----

def test_jpeg_keeps_only_whitelisted_timestamps() -> None:
    src = make_jpeg(exif=build_exif())

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    ex = out.getexif()
    assert ex.get(306) == TS
    assert ex.get(305) is None  # Software dropped
    sub = ex.get_ifd(0x8769)
    assert sub.get(36867) == TS2
    assert sub.get(37510) is None  # UserComment dropped
    assert dict(ex.get_ifd(0x8825)) == {}  # GPS dropped
    assert out.info.get("comment") is None


def test_jpeg_com_webshell_is_not_carried_over() -> None:
    src = make_jpeg(comment=b"<?php evil(); ?>")
    assert b"\xff\xfe" in src  # input really has COM

    result = sanitize(src, isolation="none")

    assert b"\xff\xfe" not in result.data
    assert b"<?php" not in result.data


def test_png_timestamps_survive_via_fresh_exif() -> None:
    src = png_insert_chunk(make_png(), b"eXIf", build_exif()[6:])

    result = sanitize(src, isolation="none")

    ex = Image.open(io.BytesIO(result.data)).getexif()
    assert ex.get(306) == TS
    assert ex.get(305) is None


def test_malformed_whitelisted_timestamp_is_rejected() -> None:
    src = make_jpeg(exif=build_exif(dto="Tuesday", dt="also not a date"))
    with pytest.raises(MetadataInvalid) as ei:
        sanitize(src, isolation="none")
    assert ei.value.reason is RejectionReason.METADATA_INVALID
