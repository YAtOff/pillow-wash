"""Slice 6: orientation is Baked into pixels; the tag never survives.

Seam: public `sanitize()`; expected pixels computed independently via
Pillow's own `exif_transpose` on the raw input.
"""

from __future__ import annotations

import io

from PIL import Image, ImageOps

from image_sanitizer import sanitize

from imgfactory import make_jpeg, make_png, png_insert_chunk


def build_exif_with_orientation(orientation: int, extra=None) -> bytes:
    ex = Image.Exif()
    ex[274] = orientation
    if extra:
        ex.update(extra)
    return ex.tobytes()


def make_gradient(size=(7, 3), mode="RGB") -> Image.Image:
    w, h = size
    im = Image.new(mode, size)
    px = im.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 30) % 256, (y * 30) % 256, ((x + y) * 10) % 256)
    return im


def test_jpeg_orientation_6_is_baked_and_tag_dropped() -> None:
    buf = io.BytesIO()
    make_gradient().save(buf, "JPEG", quality=95, exif=build_exif_with_orientation(6))
    src = buf.getvalue()

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    assert out.getexif().get(274) is None
    expected = ImageOps.exif_transpose(Image.open(io.BytesIO(src))).convert("RGB")
    assert out.size == expected.size
    # JPEG in -> JPEG out is the visually-lossless contract: one extra
    # generation at q95, bounded here rather than demanded byte-exact.
    from PIL import ImageChops, ImageStat

    diff = ImageChops.difference(out.convert("RGB"), expected)
    mean = max(ImageStat.Stat(diff).mean)
    peak = diff.getextrema()
    assert mean < 4.0, f"generation loss too high: mean {mean}"
    assert all(p[1] < 40 for p in peak), f"generation loss spike: {peak}"
    assert any(a.kind == "baked" for a in result.report.actions)


def test_png_orientation_is_baked_and_tag_dropped() -> None:
    src = png_insert_chunk(
        _png_bytes(make_gradient()),
        b"eXIf",
        build_exif_with_orientation(8)[6:],
    )

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    assert out.getexif().get(274) is None
    raw = _png_bytes(make_gradient())
    expected = ImageOps.exif_transpose(
        Image.open(io.BytesIO(png_insert_chunk(raw, b"eXIf", build_exif_with_orientation(8)[6:])))
    ).convert("RGB")
    assert out.convert("RGB").tobytes() == expected.tobytes()


def test_unrotated_image_gets_no_bake_action() -> None:
    result = sanitize(make_png(size=(5, 4)), isolation="none")
    assert not any(a.kind == "baked" for a in result.report.actions)


def _png_bytes(im: Image.Image) -> bytes:
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()
