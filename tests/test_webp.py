"""Slice 10: WebP — still + animated, lossless detection, chunk hygiene.

Seam: public `sanitize()`; expectations computed by independent RIFF walks
and Pillow decodes of the raw input.
"""

from __future__ import annotations

import io

from PIL import Image

from image_sanitizer import sanitize


def webp_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    out = []
    pos = 12
    while pos + 8 <= len(data):
        fourcc = data[pos : pos + 4]
        sz = int.from_bytes(data[pos + 4 : pos + 8], "little")
        out.append((fourcc, data[pos + 8 : pos + 8 + sz]))
        pos += 8 + sz + (sz & 1)
    return out


def anmf_durations(data: bytes) -> list[int]:
    durs = []
    for fourcc, payload in webp_chunks(data):
        if fourcc == b"ANMF":
            durs.append(payload[12] | payload[13] << 8 | payload[14] << 16)
    return durs


def make_webp(size=(9, 6), color=(90, 120, 30), **kw) -> bytes:
    im = Image.new("RGB", size, color)
    buf = io.BytesIO()
    im.save(buf, "WEBP", **kw)
    return buf.getvalue()


def gradient_webp(size=(12, 9)) -> bytes:
    w, h = size
    im = Image.new("RGB", size)
    px = im.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 21) % 256, (y * 23) % 256, ((x + y) * 17) % 256)
    buf = io.BytesIO()
    im.save(buf, "WEBP", quality=95)
    return buf.getvalue()


def test_lossy_webp_comes_back_visually_lossless() -> None:
    from PIL import ImageChops, ImageStat

    src = gradient_webp()

    result = sanitize(src, isolation="none")

    assert result.data[:4] == b"RIFF" and result.data[8:12] == b"WEBP"
    a = Image.open(io.BytesIO(src)).convert("RGB")
    b = Image.open(io.BytesIO(result.data)).convert("RGB")
    diff = ImageChops.difference(a, b)
    assert max(ImageStat.Stat(diff).mean) < 4.0


def test_lossless_webp_roundtrips_bit_exact() -> None:
    src = make_webp(lossless=True)
    assert any(c == b"VP8L" for c, _ in webp_chunks(src))

    result = sanitize(src, isolation="none")

    a = Image.open(io.BytesIO(src)).convert("RGB")
    b = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert a.tobytes() == b.tobytes()
    assert any(c == b"VP8L" for c, _ in webp_chunks(result.data))


def test_animated_webp_preserves_frames_timing_loop() -> None:
    frames = [Image.new("RGB", (8, 8), (i * 60, 20, 20)) for i in range(3)]
    buf = io.BytesIO()
    frames[0].save(
        buf, "WEBP", save_all=True, append_images=frames[1:],
        duration=[120, 140, 160], loop=2,
    )
    src = buf.getvalue()

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    assert out.n_frames == 3
    assert anmf_durations(src) == anmf_durations(result.data) == [120, 140, 160]
    assert out.info.get("loop") == 2


def test_webp_xmp_chunk_is_dropped() -> None:
    src = make_webp(xmp=b"<x:xmpmeta xmlns:x='adobe:ns:meta/'>evil</x:xmpmeta>")
    assert any(c == b"XMP " for c, _ in webp_chunks(src))

    result = sanitize(src, isolation="none")

    fourccs = [c for c, _ in webp_chunks(result.data)]
    assert b"XMP " not in fourccs
    assert b"adobe:ns" not in result.data


def test_webp_timestamps_survive() -> None:
    ex = Image.Exif()
    ex[306] = "2023:01:02 03:04:05"
    ex[271] = "Where I live"  # Location tag: not whitelisted
    src = make_webp(exif=ex.tobytes())

    result = sanitize(src, isolation="none")

    exif = Image.open(io.BytesIO(result.data)).getexif()
    assert exif.get(306) == "2023:01:02 03:04:05"
    assert exif.get(271) is None
