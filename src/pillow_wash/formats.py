"""Format sniffing: what is this byte stream, independent of any declaration."""

from __future__ import annotations

import re

__all__ = ["SUPPORTED_FORMATS", "canonical", "sniff", "unsupported_detail"]

SUPPORTED_FORMATS = ("PNG", "JPEG", "GIF", "WEBP", "BMP", "TIFF")

_KNOWN_UNSUPPORTED = {
    "SVG": "SVG is a document format, not an image container; out of scope",
    "HEIC": "HEIC/AVIF is out of scope for v1",
}

_ALIASES = {
    "jpg": "JPEG",
    "jpeg": "JPEG",
    "jpe": "JPEG",
    "png": "PNG",
    "gif": "GIF",
    "webp": "WEBP",
    "bmp": "BMP",
    "dib": "BMP",
    "tif": "TIFF",
    "tiff": "TIFF",
}

_HEIC_BRANDS = {
    b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis", b"hevm", b"hevs",
    b"mif1", b"msf1", b"miaf", b"avif", b"avis",
}

_SVG_RE = re.compile(rb"<svg[\s>]", re.IGNORECASE)


def canonical(name: str) -> str | None:
    """Map a declared name or filename extension to a canonical format name."""
    return _ALIASES.get(name.strip().lower().lstrip("."))


def sniff(data: bytes) -> str:
    """Return a canonical format name for known magics, else ``"UNKNOWN"``.

    Binary magics are checked first, so text-based detection (SVG) can never
    misfire on a container that happens to carry markup in its payload.
    """
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "GIF"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP"
    if data[:2] == b"BM":
        return "BMP"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return "TIFF"
    if data[4:8] == b"ftyp" and data[8:12] in _HEIC_BRANDS:
        return "HEIC"
    head = bytes(data[:4096]).lstrip(b"\xef\xbb\xbf \t\r\n")
    if head[:1] == b"<" and _SVG_RE.search(head):
        return "SVG"
    return "UNKNOWN"


def unsupported_detail(fmt: str) -> str:
    if fmt in _KNOWN_UNSUPPORTED:
        return f"{fmt}: {_KNOWN_UNSUPPORTED[fmt]}"
    return "unrecognized byte stream: no known image magic"
