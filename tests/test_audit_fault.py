"""Slice 11: the Audit catches a betraying encoder.

Seam: public `sanitize()` — we inject an encoder that smuggles input-derived
structure into the output and demand the Audit turn it into a Rejection.
"""

from __future__ import annotations

import io

import pytest

from pillow_wash import AuditFailed, RejectionReason, sanitize
from pillow_wash import pipeline

from imgfactory import make_png, png_insert_chunk


def test_betrayed_encoder_smuggling_text_chunk_is_rejected(monkeypatch) -> None:
    def evil_encoder(im, wl):
        out = pipeline._encode_png(im, wl)
        return png_insert_chunk(out, b"tEXt", b"Comment\x00smuggled")

    monkeypatch.setitem(pipeline._ENCODERS, "PNG", evil_encoder)

    with pytest.raises(AuditFailed) as ei:
        sanitize(make_png(), isolation="none")
    assert ei.value.reason is RejectionReason.AUDIT_FAILED
    assert "tEXt" in ei.value.detail


def test_betrayed_encoder_appending_trailing_data_is_rejected(monkeypatch) -> None:
    def evil_encoder(im, wl):
        return pipeline._encode_png(im, wl) + b"trailing junk"

    monkeypatch.setitem(pipeline._ENCODERS, "PNG", evil_encoder)

    with pytest.raises(AuditFailed):
        sanitize(make_png(), isolation="none")


def test_passthrough_betrayal_is_rejected(monkeypatch) -> None:
    # The ultimate betrayal: "sanitize" by returning the input untouched.
    smuggled = png_insert_chunk(make_png(), b"tEXt", b"Comment\x00<?php ?>")

    def passthrough(im, wl):
        return smuggled

    monkeypatch.setitem(pipeline._ENCODERS, "PNG", passthrough)

    with pytest.raises(AuditFailed):
        sanitize(smuggled, isolation="none")


def test_audit_allows_exactly_what_was_written() -> None:
    # Control: the real encoder's output passes its own audit (no false
    # positives that would make every Clean result a Rejection).
    result = sanitize(make_png(size=(6, 4)), isolation="none")
    assert result.data[:4] == b"\x89PNG"
