"""The rebuild pipeline: decode -> whitelist -> re-encode -> audit.

Runs unchanged in-process or inside the Sandbox worker; it performs no I/O
of its own (bytes in, bytes out) so it composes with any isolation model.
"""

from __future__ import annotations

import hashlib
import io
import re
import time
from dataclasses import dataclass

from PIL import Image, ImageOps, UnidentifiedImageError

from .audit import AuditViolation, audit
from .exceptions import (
    AuditFailed,
    LimitExceeded,
    MetadataInvalid,
    RejectionError,
    Undecodable,
    UnsupportedFormat,
)
from . import formats
from .report import Action, Report

__all__ = ["sanitize_bytes"]


@dataclass(frozen=True)
class _Timing:
    """Animation parameters — Visual Information, captured before info clear."""

    durations: tuple[int, ...] = ()
    loop: int | None = None
    transparency: int | None = None  # still-GIF palette index
    lossless: bool = False  # WebP: input was VP8L


@dataclass(frozen=True)
class _Whitelist:
    """What the Metadata Whitelist extracted from the input, to re-attach."""

    icc: bytes | None = None
    exif: bytes | None = None  # freshly built EXIF carrying only vetted tags
    timing: _Timing | None = None
    actions: tuple[Action, ...] = ()


# ---------------------------------------------------------------- decode ----

def _decode(data: bytes, limits, fmt: str) -> Image.Image:
    try:
        im = Image.open(io.BytesIO(data), formats=[fmt])
        w, h = im.size
        frames = getattr(im, "n_frames", 1)
        if w == 0 or h == 0:
            raise Undecodable(f"{fmt}: zero-sized image")
        if max(w, h) > limits.max_dimension:
            raise LimitExceeded(
                f"{fmt}: dimension {w}x{h} exceeds max_dimension {limits.max_dimension}"
            )
        if fmt == "TIFF" and frames > 1:
            raise LimitExceeded("TIFF: multi-page not supported")
        if frames > limits.max_frames:
            raise LimitExceeded(
                f"{fmt}: {frames} frames exceeds max_frames {limits.max_frames}"
            )
        if frames == 1 and w * h > limits.max_still_pixels:
            raise LimitExceeded(
                f"{fmt}: {w * h} pixels exceeds max_still_pixels {limits.max_still_pixels}"
            )
        if w * h * frames > limits.max_total_pixels:
            raise LimitExceeded(
                f"{fmt}: {w * h * frames} cumulative pixels exceeds "
                f"max_total_pixels {limits.max_total_pixels}"
            )
        im.load()
        return im
    except RejectionError:
        raise
    except UnidentifiedImageError as e:
        raise Undecodable(f"{fmt}: no decoder accepted the bytes") from e
    except Image.DecompressionBombError as e:
        raise LimitExceeded(f"{fmt}: engine pixel guard tripped") from e
    except (OSError, ValueError, SyntaxError) as e:
        raise Undecodable(f"{fmt}: decode failed: {e}") from e


# ---------------------------------------------------------------- encode ----

def _encode_png(im: Image.Image, wl: _Whitelist) -> bytes:
    im.info.clear()  # kill carry-overs (iCCP/tRNS/text) — we re-attach by kwargs only
    buf = io.BytesIO()
    im.save(
        buf,
        "PNG",
        icc_profile=wl.icc,  # explicit None suppresses auto-carry
        exif=wl.exif if wl.exif else b"",
    )
    return buf.getvalue()


def _encode_jpeg(im: Image.Image, wl: _Whitelist) -> bytes:
    im.info.clear()  # kill the COM carry-over path
    if im.mode not in ("RGB", "L", "CMYK"):
        im = im.convert("RGB")
    buf = io.BytesIO()
    im.save(
        buf,
        "JPEG",
        quality=95,
        subsampling=0,  # 4:4:4: fidelity-first; chroma sub-sampling is visible loss
        exif=wl.exif if wl.exif else b"",
        icc_profile=wl.icc,
    )
    return buf.getvalue()


def _encode_gif(im: Image.Image, wl: _Whitelist) -> bytes:
    im.info.clear()
    timing = wl.timing or _Timing()
    buf = io.BytesIO()
    if getattr(im, "n_frames", 1) > 1:
        from PIL import ImageSequence

        im.seek(0)
        frames: list[Image.Image] = []
        for fr in ImageSequence.Iterator(im):
            if fr.info.get("transparency") is not None:
                fr = fr.convert("RGBA")
            frames.append(fr.copy())
        kw: dict = {"save_all": True, "append_images": frames[1:]}
        if timing.durations:
            kw["duration"] = list(timing.durations)
        if timing.loop is not None:
            kw["loop"] = timing.loop
        frames[0].save(buf, "GIF", **kw)
    else:
        kw = {}
        if timing.transparency is not None:
            kw["transparency"] = timing.transparency
        im.save(buf, "GIF", **kw)
    return buf.getvalue()


def _encode_bmp(im: Image.Image, wl: _Whitelist) -> bytes:
    im.info.clear()
    buf = io.BytesIO()
    im.save(buf, "BMP")
    return buf.getvalue()


def _encode_webp(im: Image.Image, wl: _Whitelist) -> bytes:
    im.info.clear()
    if im.mode not in ("RGB", "RGBA"):
        im = im.convert("RGBA")
    timing = wl.timing or _Timing()
    buf = io.BytesIO()
    if getattr(im, "n_frames", 1) > 1:
        from PIL import ImageSequence

        im.seek(0)
        frames = [f.copy() for f in ImageSequence.Iterator(im)]
        kw: dict = {"save_all": True, "append_images": frames[1:]}
        if timing.durations:
            kw["duration"] = list(timing.durations)
        if timing.loop is not None:
            kw["loop"] = timing.loop
        if timing.lossless:
            kw["lossless"] = True
        else:
            kw["quality"] = 95
        kw["exif"] = wl.exif if wl.exif else b""
        kw["icc_profile"] = wl.icc
        frames[0].save(buf, "WEBP", **kw)
    else:
        kw = {"exif": wl.exif if wl.exif else b"", "icc_profile": wl.icc}
        if timing.lossless:
            kw["lossless"] = True
        else:
            kw["quality"] = 95
        im.save(buf, "WEBP", **kw)
    return buf.getvalue()


def _encode_tiff(im: Image.Image, wl: _Whitelist) -> bytes:
    # Pillow's TIFF writer re-reads tag_v2 of a TIFF-opened image (resolution, XMP,
    # IPTC, Photoshop); a plain copy carries pixels and palette only.
    im = im.copy()
    im.info.clear()
    buf = io.BytesIO()
    im.save(
        buf,
        "TIFF",
        compression="raw",
        icc_profile=wl.icc,
        exif=wl.exif if wl.exif else b"",
    )
    return buf.getvalue()


_ENCODERS = {
    "PNG": _encode_png,
    "JPEG": _encode_jpeg,
    "GIF": _encode_gif,
    "BMP": _encode_bmp,
    "WEBP": _encode_webp,
    "TIFF": _encode_tiff,
}


# --------------------------------------------------------------- pipeline ---

def sanitize_bytes(
    data: bytes,
    limits,
    output_format: str | None,
    declared_format: str | None,
) -> tuple[bytes, Report]:
    """Run the full pipeline. Returns ``(clean_bytes, report)`` or raises."""
    t0 = time.perf_counter()
    actions: list[Action] = []

    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sanitize() accepts bytes-like input")
    data = bytes(data)
    if len(data) == 0:
        raise UnsupportedFormat("empty input")
    if len(data) > limits.max_input_bytes:
        raise LimitExceeded(
            f"input is {len(data)} bytes; max_input_bytes is {limits.max_input_bytes}"
        )

    fmt = formats.sniff(data)
    if fmt not in formats.SUPPORTED_FORMATS:
        raise UnsupportedFormat(formats.unsupported_detail(fmt))

    declared = formats.canonical(declared_format) if declared_format else None
    if declared_format and declared is None:
        raise ValueError(f"declared_format {declared_format!r} is not a known format")
    mismatch = declared is not None and declared != fmt

    out_fmt = formats.canonical(output_format) if output_format else fmt
    if output_format and out_fmt is None:
        raise ValueError(f"output_format {output_format!r} is not a known format")
    if out_fmt not in formats.SUPPORTED_FORMATS:
        raise UnsupportedFormat(f"output_format {out_fmt} is not supported")

    im = _decode(data, limits, fmt)

    if out_fmt not in _ENCODERS:
        raise NotImplementedError(f"encoder for {out_fmt} lands in a later slice")

    im = _bake_orientation(im, actions)

    wl = _extract_whitelist(im, fmt, limits, actions, raw=data)
    im.info.clear()  # nothing rides along implicitly

    out = _ENCODERS[out_fmt](im, wl)

    try:
        audit(out, out_fmt, expect_icc=wl.icc is not None, expect_exif=wl.exif is not None)
    except AuditViolation as e:
        raise AuditFailed(f"{out_fmt}: output audit failed: {e}") from e

    duration_ms = (time.perf_counter() - t0) * 1000.0
    report = Report(
        input_format=fmt,
        output_format=out_fmt,
        declared_format=declared,
        mismatch=mismatch,
        width=im.size[0],
        height=im.size[1],
        frames=getattr(im, "n_frames", 1),
        actions=tuple(actions) + wl.actions,
        limits=limits,
        input_sha256=hashlib.sha256(data).hexdigest(),
        output_sha256=hashlib.sha256(out).hexdigest(),
        duration_ms=duration_ms,
    )
    return out, report


def _bake_orientation(im: Image.Image, actions: list[Action]) -> Image.Image:
    """Apply EXIF orientation to the pixel grid; the tag never survives.

    Visual Information is bit-exact *as displayed*, so a rotated stored grid
    is transposed to upright at rebuild time rather than re-attaching the
    tag. Animated inputs keep their stored grid (per-frame transposition is
    not attempted in v1) and the tag is dropped with a Report note.
    """
    orientation = None
    try:
        orientation = im.getexif().get(274)
    except (OSError, ValueError):
        pass
    if orientation in (None, 1):
        return im
    if getattr(im, "n_frames", 1) > 1:
        actions.append(
            Action("dropped", f"orientation {orientation} on animated input dropped without baking")
        )
        return im
    im = ImageOps.exif_transpose(im) or im
    actions.append(Action("baked", f"orientation {orientation} baked into pixels"))
    return im


def _extract_whitelist(
    im: Image.Image, fmt: str, limits, actions: list[Action], raw: bytes = b""
) -> _Whitelist:
    """Pull vetted items out of decoded info; everything else is dropped.

    Whitelist (v1): capture timestamps (EXIF 306 DateTime, 36867
    DateTimeOriginal) with strict format validation, and (from slice 7) an
    ICC profile under validation. Nothing else survives the rebuild.
    """
    ts_re = re.compile(r"^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$")
    wl_actions: list[Action] = []
    dropped = 0
    kept: dict[int, str] = {}

    def check_ts(tag: int, value: object) -> str:
        if not isinstance(value, str) or not ts_re.match(value):
            raise MetadataInvalid(
                f"whitelisted EXIF tag {tag} is malformed: {value!r}"
            )
        return value

    try:
        exif_raw = im.getexif()
    except (OSError, ValueError) as e:
        raise Undecodable(f"{fmt}: EXIF structure unreadable: {e}") from e

    if exif_raw:
        if exif_raw.get(306) is not None:
            kept[306] = check_ts(306, exif_raw.get(306))
        sub = exif_raw.get_ifd(0x8769)
        if sub.get(36867) is not None:
            kept[36867] = check_ts(36867, sub.get(36867))
        gps = exif_raw.get_ifd(0x8825)
        if len(gps):
            dropped += len(gps)
            wl_actions.append(Action("dropped", "GPS metadata dropped"))
        dropped += max(len(exif_raw) - (1 if 306 in kept else 0), 0)
        dropped += max(len(sub) - (1 if 36867 in kept else 0), 0)

    text = getattr(im, "text", None) or {}
    if text:
        dropped += len(text)
    if im.info.get("comment"):
        dropped += 1  # JPEG COM
    if im.info.get("xmp") or im.info.get("XMP"):
        dropped += 1

    if dropped:
        wl_actions.append(
            Action("dropped", f"{dropped} non-whitelisted metadata items dropped")
        )

    exif: bytes | None = None
    if kept:
        ex = Image.Exif()
        if 306 in kept:
            ex[306] = kept[306]
        if 36867 in kept:
            ex.get_ifd(0x8769)[36867] = kept[36867]
        exif = ex.tobytes()
        wl_actions.append(Action("kept", "capture timestamps re-attached"))

    icc: bytes | None = None
    raw_icc = im.info.get("icc_profile")
    if raw_icc:
        raw_icc = bytes(raw_icc)
        if len(raw_icc) > limits.icc_max_bytes:
            raise MetadataInvalid(
                f"ICC profile is {len(raw_icc)} bytes; icc_max_bytes is {limits.icc_max_bytes}"
            )
        try:
            from PIL import ImageCms

            ImageCms.ImageCmsProfile(io.BytesIO(raw_icc))  # lcms2 parse = validation
        except Exception as e:
            raise MetadataInvalid(f"ICC profile failed validation: {e}") from e
        icc = raw_icc
        wl_actions.append(Action("kept", "ICC profile re-attached (validated)"))

    timing: _Timing | None = None
    if fmt == "GIF":
        if getattr(im, "n_frames", 1) > 1:
            from PIL import ImageSequence

            im.seek(0)
            durations = []
            has_transparency = False
            for fr in ImageSequence.Iterator(im):
                durations.append(fr.info.get("duration") or 0)
                if fr.info.get("transparency") is not None:
                    has_transparency = True
            timing = _Timing(
                durations=tuple(durations),
                loop=im.info.get("loop"),
                transparency=0 if has_transparency else None,
            )
            wl_actions.append(
                Action("kept", f"{len(durations)} frames with original timing re-encoded")
            )
        elif im.info.get("transparency") is not None:
            t = im.info["transparency"]
            if isinstance(t, int) and 0 <= t <= 255:
                timing = _Timing(transparency=t)
                wl_actions.append(Action("kept", "GIF transparency index re-attached"))
    elif fmt == "WEBP":
        from .audit import webp_chunks

        try:
            chunks = list(webp_chunks(raw))
        except Exception:
            chunks = []
        lossless = any(c == b"VP8L" for c, _ in chunks) or any(
            p.find(b"VP8L", 16, 24) >= 0 for c, p in chunks if c == b"ANMF"
        )
        if getattr(im, "n_frames", 1) > 1:
            durations = tuple(
                p[12] | p[13] << 8 | p[14] << 16
                for c, p in chunks
                if c == b"ANMF"
            )
            timing = _Timing(
                durations=durations,
                loop=im.info.get("loop"),
                lossless=lossless,
            )
            wl_actions.append(
                Action("kept", f"{len(durations)} frames with original timing re-encoded")
            )
        elif lossless:
            timing = _Timing(lossless=True)

    return _Whitelist(icc=icc, exif=exif, timing=timing, actions=tuple(wl_actions))
