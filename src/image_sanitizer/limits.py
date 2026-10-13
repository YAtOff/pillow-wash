"""Resource limits: the Bomb policy. Every exceedance is a Rejection."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

__all__ = ["Limits"]


@dataclass(frozen=True)
class Limits:
    """Caller-overridable bounds applied before and during decode.

    Defaults are conservative for Ingest pipelines; every limit can be
    relaxed per call (``sanitize(data, limits=Limits(max_input_bytes=...))``).
    """

    max_input_bytes: int = 100 * 1024 * 1024  # 100 MB encoded input
    max_still_pixels: int = 50_000_000  # 50 MP for single-frame images
    max_total_pixels: int = 200_000_000  # 200 MP cumulative for animated
    max_frames: int = 1000
    max_dimension: int = 16383  # aligns with the strictest engine cap (WebP)
    icc_max_bytes: int = 1024 * 1024  # 1 MiB for a whitelisted ICC profile
    timeout_seconds: float = 30.0  # wall clock for one Sanitize call

    def relaxed(self, **changes: int | float) -> "Limits":
        return replace(self, **changes)
