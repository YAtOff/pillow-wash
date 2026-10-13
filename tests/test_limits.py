"""Slice 4: the Bomb policy — every limit exceedance is a LimitExceeded Rejection."""

from __future__ import annotations

import pytest

from image_sanitizer import LimitExceeded, Limits, RejectionReason, sanitize

from imgfactory import make_gif, make_png, patch_png_ihdr


def test_input_size_cap() -> None:
    src = make_png()
    with pytest.raises(LimitExceeded) as ei:
        sanitize(src, limits=Limits(max_input_bytes=16), isolation="none")
    assert ei.value.reason is RejectionReason.LIMIT_EXCEEDED
    assert "max_input_bytes" in ei.value.detail


def test_still_pixel_cap_fires_before_decode() -> None:
    # 7500x7500 = 56.25 MP: above our 50 MP default, below Pillow's own guard
    src = patch_png_ihdr(make_png(), 7500, 7500)
    with pytest.raises(LimitExceeded) as ei:
        sanitize(src, isolation="none")
    assert "max_still_pixels" in ei.value.detail


def test_pixel_cap_is_relaxable() -> None:
    src = make_png(size=(8, 6))  # 48 px
    with pytest.raises(LimitExceeded):
        sanitize(src, limits=Limits(max_still_pixels=47), isolation="none")
    result = sanitize(src, limits=Limits(max_still_pixels=48), isolation="none")
    assert result.data[:4] == b"\x89PNG"


def test_dimension_cap() -> None:
    src = patch_png_ihdr(make_png(), 20000, 8)  # 160 kp, within pixel caps
    with pytest.raises(LimitExceeded) as ei:
        sanitize(src, isolation="none")
    assert "max_dimension" in ei.value.detail


def test_frame_cap() -> None:
    src = make_gif(frames=((200, 30, 40), (30, 200, 40), (30, 40, 200)))
    with pytest.raises(LimitExceeded) as ei:
        sanitize(src, limits=Limits(max_frames=2), isolation="none")
    assert "max_frames" in ei.value.detail
