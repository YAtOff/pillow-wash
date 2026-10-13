"""The Report: actions taken during one Sanitize call — never verdicts."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

__all__ = ["Action", "Report", "SanitizedImage"]


@dataclass(frozen=True)
class Action:
    """One action the library took while rebuilding (e.g. dropped EXIF)."""

    kind: str
    detail: str


@dataclass(frozen=True)
class Report:
    input_format: str
    output_format: str
    declared_format: str | None
    mismatch: bool
    width: int
    height: int
    frames: int
    actions: tuple[Action, ...]
    limits: Any  # Limits (avoided import cycle; structurally a Limits)
    input_sha256: str
    output_sha256: str
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["actions"] = [
            {"kind": a.kind, "detail": a.detail} for a in self.actions
        ]
        return d


@dataclass(frozen=True)
class SanitizedImage:
    """A Clean image plus its Report. The only success result."""

    data: bytes
    report: Report
