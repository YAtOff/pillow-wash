"""Public API: sanitize() with the two isolation modes."""

from __future__ import annotations

from enum import Enum

from .limits import Limits
from .report import SanitizedImage

__all__ = ["Isolation", "sanitize"]


class Isolation(str, Enum):
    """Where the untrusted decode runs.

    SANDBOX (default): a sacrificial worker process with rlimits and a
    wall-clock timeout. NONE: in-process, for tests and development only —
    see ADR-0002 for why the default is what it is.
    """

    SANDBOX = "sandbox"
    NONE = "none"


def sanitize(
    data: bytes,
    *,
    limits: Limits | None = None,
    output_format: str | None = None,
    isolation: Isolation | str = Isolation.SANDBOX,
    declared_format: str | None = None,
) -> SanitizedImage:
    """Sanitize an untrusted image by whitelist-rebuild.

    Returns a :class:`SanitizedImage` (Clean bytes + Report) or raises a
    :class:`RejectionError` subclass. There is no third outcome.
    """
    limits = limits if limits is not None else Limits()
    mode = Isolation(isolation)
    if mode is Isolation.NONE:
        from .pipeline import sanitize_bytes

        out, report = sanitize_bytes(data, limits, output_format, declared_format)
        return SanitizedImage(out, report)
    from .sandbox import run_sandboxed

    return run_sandboxed(
        data,
        {
            "limits": limits,
            "output_format": output_format,
            "declared_format": declared_format,
        },
    )
