"""pillow-wash: clean pixels, vetted metadata, nothing inherited."""

from .exceptions import (
    AuditFailed,
    LimitExceeded,
    MetadataInvalid,
    RejectionError,
    RejectionReason,
    SandboxCrash,
    Undecodable,
    UnsupportedFormat,
)
from .limits import Limits
from .report import Action, Report, SanitizedImage
from .sanitizer import Isolation, sanitize

__version__ = "0.1.0"

__all__ = [
    "sanitize",
    "Isolation",
    "Limits",
    "SanitizedImage",
    "Report",
    "Action",
    "RejectionError",
    "RejectionReason",
    "UnsupportedFormat",
    "Undecodable",
    "LimitExceeded",
    "MetadataInvalid",
    "SandboxCrash",
    "AuditFailed",
]
