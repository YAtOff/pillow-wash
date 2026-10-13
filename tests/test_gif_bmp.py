"""Slice 9: fidelity — GIF/BMP roundtrips, animated timing, GIF-borne attacks.

Seam: public `sanitize()`; expectations computed by independent Pillow
decodes of the raw input.
"""

from __future__ import annotations

import io

from PIL import Image, ImageSequence

from pillow_wash import sanitize

from imgfactory import make_bmp, make_gif


def frames_rgba(data: bytes) -> list[Image.Image]:
    im = Image.open(io.BytesIO(data))
    return [f.convert("RGBA") for f in ImageSequence.Iterator(im)]


def frame_durations(data: bytes) -> list[int]:
    im = Image.open(io.BytesIO(data))
    return [f.info.get("duration") for f in ImageSequence.Iterator(im)]


def test_still_gif_roundtrips_pixel_exact() -> None:
    src = make_gif(frames=((200, 30, 40),))

    result = sanitize(src, isolation="none")

    assert result.data[:3] == b"GIF"
    assert frames_rgba(src)[0].tobytes() == frames_rgba(result.data)[0].tobytes()


def test_animated_gif_preserves_frames_pixels_timing_loop() -> None:
    src = make_gif(
        frames=((200, 30, 40), (30, 200, 40), (30, 40, 200)),
        durations=[100, 250, 80],
    )
    # make_gif writes loop=0 (forever)
    in_frames = frames_rgba(src)

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    assert out.n_frames == 3
    assert frame_durations(src) == frame_durations(result.data) == [100, 250, 80]
    out_frames = frames_rgba(result.data)
    for a, b in zip(in_frames, out_frames):
        assert a.tobytes() == b.tobytes()
    assert Image.open(io.BytesIO(result.data)).info.get("loop") == 0


def test_partial_frame_gif_preserves_composited_visuals() -> None:
    # second frame is smaller: compositing must match what a renderer shows
    f1 = Image.new("P", (20, 20))
    f1.putpalette([200, 30, 40] + [0, 0, 0] * 255)
    f2 = Image.new("P", (8, 8))
    f2.putpalette([30, 200, 40] + [0, 0, 0] * 255)
    buf = io.BytesIO()
    f1.save(buf, "GIF", save_all=True, append_images=[f2], duration=[70, 90])
    src = buf.getvalue()
    in_frames = frames_rgba(src)

    result = sanitize(src, isolation="none")

    out_frames = frames_rgba(result.data)
    assert len(out_frames) == 2
    for a, b in zip(in_frames, out_frames):
        assert a.tobytes() == b.tobytes()


def test_gif_trailing_payload_is_dropped() -> None:
    src = make_gif() + b"<?php system($_GET['c']); ?>"

    result = sanitize(src, isolation="none")

    assert result.data.endswith(b"\x3b")
    assert b"<?php" not in result.data


def test_gif_comment_extension_is_dropped() -> None:
    src = make_gif()
    assert src.endswith(b"\x3b")
    evil = b"\x21\xfe\x0e<?php evil(); ?>\x00"
    src = src[:-1] + evil + b"\x3b"
    probe = Image.open(io.BytesIO(src))
    probe.load()
    assert probe.format == "GIF"  # input is still a decodable GIF

    result = sanitize(src, isolation="none")

    assert b"\x21\xfe" not in result.data
    assert b"<?php" not in result.data


def test_bmp_roundtrips_pixel_exact() -> None:
    src = make_bmp(size=(9, 5))

    result = sanitize(src, isolation="none")

    assert result.data[:2] == b"BM"
    a = Image.open(io.BytesIO(src)).convert("RGB")
    b = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert a.tobytes() == b.tobytes()
