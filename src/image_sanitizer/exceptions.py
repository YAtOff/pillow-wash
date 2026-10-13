"""Rejection taxonomy: the six stable reasons a Sanitize call can refuse input.

The set is closed and additive-only across versions (see CONTEXT.md,
"Rejection Reason"). A Rejection is the *only* alternative to a Clean result.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "RejectionReason",
    "RejectionError",
    "UnsupportedFormat",
    "Undecodable",
    "LimitExceeded",
    "MetadataInvalid",
    "SandboxCrash",
    "AuditFailed",
]


class RejectionReason(str, Enum):
    """Stable, branchable category explaining a Rejection."""

    UNSUPPORTED_FORMAT = "UnsupportedFormat"
    UNDECODABLE = "Undecodable"
    LIMIT_EXCEEDED = "LimitExceeded"
    METADATA_INVALID = "MetadataInvalid"
    SANDBOX_CRASH = "SandboxCrash"
    AUDIT_FAILED = "AuditFailed"


class RejectionError(Exception):
    """Refusal to produce output for an input, with a reason and detail."""

    reason: RejectionReason | None = None

    def __init__(
        self,
        detail: str = "",
        *,
        report: object | None = None,
        reason: RejectionReason | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.report = report
        if reason is not None:
            self.reason = reason
        if self.reason is None:
            raise TypeError("RejectionError requires a concrete RejectionReason")


class UnsupportedFormat(RejectionError):
    reason = RejectionReason.UNSUPPORTED_FORMAT


class Undecodable(RejectionError):
    reason = RejectionReason.UNDECODABLE


class LimitExceeded(RejectionError):
    reason = RejectionReason.LIMIT_EXCEEDED


class MetadataInvalid(RejectionError):
    reason = RejectionReason.METADATA_INVALID


class SandboxCrash(RejectionError):
    reason = RejectionReason.SANDBOX_CRASH


class AuditFailed(RejectionError):
    reason = RejectionReason.AUDIT_FAILED
