"""Slice 12: the Sandbox — default isolation, crash/timeout mappings.

Seam: public `sanitize()` with the default (sandbox) isolation. Faults are
injected through the documented IMAGE_SANITIZER_FAULT environment hook so
the worker (a fresh spawned process) actually misbehaves.
"""

from __future__ import annotations

import pytest

from image_sanitizer import (
    Limits,
    RejectionReason,
    SandboxCrash,
    SanitizedImage,
    Undecodable,
    UnsupportedFormat,
    sanitize,
)

from imgfactory import make_png


def test_default_isolation_is_sandbox_and_works() -> None:
    result = sanitize(make_png(size=(7, 3)))  # no isolation= override

    assert isinstance(result, SanitizedImage)
    assert result.data[:8] == b"\x89PNG\r\n\x1a\n"
    assert result.report.input_format == "PNG"


def test_sandbox_crash_maps_to_rejection(monkeypatch) -> None:
    monkeypatch.setenv("IMAGE_SANITIZER_FAULT", "exit")
    try:
        with pytest.raises(SandboxCrash) as ei:
            sanitize(make_png())
        assert ei.value.reason is RejectionReason.SANDBOX_CRASH
    finally:
        monkeypatch.delenv("IMAGE_SANITIZER_FAULT")


def test_sandbox_timeout_maps_to_rejection(monkeypatch) -> None:
    monkeypatch.setenv("IMAGE_SANITIZER_FAULT", "hang")
    try:
        with pytest.raises(SandboxCrash) as ei:
            sanitize(make_png(), limits=Limits(timeout_seconds=0.5))
        assert "wall clock" in ei.value.detail
    finally:
        monkeypatch.delenv("IMAGE_SANITIZER_FAULT")


def test_sandbox_propagates_rejection_reasons() -> None:
    with pytest.raises(UnsupportedFormat):
        sanitize(b"<svg xmlns='x'><script>1</script></svg>")
    with pytest.raises(Undecodable):
        sanitize(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)


def test_sandbox_rejects_hostile_metadata_too() -> None:
    from imgfactory import make_jpeg
    from PIL import Image

    ex = Image.Exif()
    ex.get_ifd(0x8769)[36867] = "not a timestamp"  # SubIFD: the whitelisted location
    with pytest.raises(Exception) as ei:
        sanitize(make_jpeg(exif=ex.tobytes()))
    from image_sanitizer import MetadataInvalid

    assert isinstance(ei.value, MetadataInvalid)


def test_in_process_mode_matches_sandbox_output() -> None:
    from PIL import Image
    import io

    src = make_png(size=(9, 4), color=(10, 200, 30))
    sandboxed = sanitize(src)
    inproc = sanitize(src, isolation="none")
    assert sandboxed.data == inproc.data  # deterministic rebuild
    a = Image.open(io.BytesIO(sandboxed.data))
    b = Image.open(io.BytesIO(src))
    assert a.convert("RGB").tobytes() == b.convert("RGB").tobytes()
