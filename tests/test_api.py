"""Slice 13: the public API surface — overrides, declarations, report shape.

Seam: `sanitize()` signature and the Report, exactly as agreed.
"""

from __future__ import annotations

import io
import json

import pytest
from PIL import Image

from pillow_wash import Isolation, Limits, SanitizedImage, sanitize

from imgfactory import make_jpeg, make_png


def test_output_format_override_canonicalizes() -> None:
    src = make_jpeg(size=(8, 5))

    result = sanitize(src, isolation="none", output_format="png")

    assert result.data[:8] == b"\x89PNG\r\n\x1a\n"
    assert result.report.output_format == "PNG"
    assert result.report.input_format == "JPEG"


def test_output_format_alias_jpg_accepted() -> None:
    result = sanitize(make_png(), isolation="none", output_format="jpg")
    assert result.report.output_format == "JPEG"
    assert result.data[:2] == b"\xff\xd8"


def test_unsupported_output_format_is_caller_error() -> None:
    with pytest.raises(ValueError):
        sanitize(make_png(), isolation="none", output_format="svg")


def test_declared_format_mismatch_is_reported_not_fatal() -> None:
    src = make_png()

    result = sanitize(src, isolation="none", declared_format="gif")

    assert result.report.declared_format == "GIF"
    assert result.report.mismatch is True
    assert result.report.input_format == "PNG"


def test_matching_declaration_reports_no_mismatch() -> None:
    result = sanitize(make_png(), isolation="none", declared_format=".png")
    assert result.report.mismatch is False


def test_unknown_declared_format_is_caller_error() -> None:
    with pytest.raises(ValueError):
        sanitize(make_png(), isolation="none", declared_format="hfgl")


def test_report_serializes_to_json() -> None:
    result = sanitize(make_png(), isolation="none")
    d = result.report.to_dict()
    blob = json.dumps(d)  # must not raise
    assert json.loads(blob)["input_format"] == "PNG"
    assert "limits" in d and "duration_ms" in d


def test_non_bytes_input_is_type_error() -> None:
    with pytest.raises(TypeError):
        sanitize(12345, isolation="none")  # type: ignore[arg-type]


def test_isolation_accepts_enum_and_string() -> None:
    assert sanitize(make_png(), isolation=Isolation.NONE).data
    assert sanitize(make_png(), isolation="none").data


def test_unknown_isolation_is_value_error() -> None:
    with pytest.raises(ValueError):
        sanitize(make_png(), isolation="container")


def test_limits_override_reaches_report() -> None:
    lim = Limits(max_input_bytes=10 * 1024 * 1024)
    result = sanitize(make_png(), isolation="none", limits=lim)
    assert result.report.limits.max_input_bytes == lim.max_input_bytes
