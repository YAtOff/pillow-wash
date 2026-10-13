"""The Audit: re-parse freshly encoded bytes and assert the structure set.

An Audit failure is a Rejection — fail-closed applies to our own encoder.
Pillow's encoders auto-carry input-derived structures (JPEG COM comments,
PNG iCCP/tRNS) unless suppressed; this module is the backstop that proves
they were.
"""

from __future__ import annotations

import struct
import zlib

__all__ = ["AuditViolation", "audit"]


class AuditViolation(Exception):
    """The freshly encoded output contains a structure we did not intend."""


def audit(data: bytes, fmt: str, **expectations: bool) -> None:
    """Assert ``data`` contains only structures the library wrote.

    Keyword expectations carry the whitelist state into the assertion:
    ``expect_icc`` / ``expect_exif`` / ``animated`` permit the corresponding
    conditional structures and nothing else.
    """
    _AUDITORS[fmt](data, expectations)


def _audit_png(data: bytes, exp: dict) -> None:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise AuditViolation("bad PNG signature")
    allowed = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}
    if exp.get("expect_icc"):
        allowed.add(b"iCCP")
    if exp.get("expect_exif"):
        allowed.add(b"eXIf")
    pos = 8
    seen: dict[bytes, int] = {}
    last_type: bytes | None = None
    while pos < len(data):
        if pos + 8 > len(data):
            raise AuditViolation("truncated chunk header")
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        if ctype not in allowed:
            raise AuditViolation(f"unexpected chunk {ctype!r}")
        end = pos + 12 + length
        if end > len(data):
            raise AuditViolation(f"chunk {ctype!r} overruns file")
        body_crc = data[pos + 8 + length : end]
        if struct.unpack(">I", body_crc)[0] != zlib.crc32(data[pos + 4 : pos + 8 + length]) & 0xFFFFFFFF:
            raise AuditViolation(f"chunk {ctype!r} fails CRC")
        seen[ctype] = seen.get(ctype, 0) + 1
        pos = end
        last_type = ctype
    if seen.get(b"IHDR", 0) != 1:
        raise AuditViolation("must contain exactly one IHDR")
    if seen.get(b"IEND", 0) != 1:
        raise AuditViolation("must contain exactly one IEND")
    if seen.get(b"IDAT", 0) < 1:
        raise AuditViolation("must contain at least one IDAT")
    if seen.get(b"PLTE", 0) > 1:
        raise AuditViolation("duplicate PLTE")
    if last_type != b"IEND":
        raise AuditViolation("IEND must be the final chunk (trailing data)")


def _audit_jpeg(data: bytes, exp: dict) -> None:
    if data[:2] != b"\xff\xd8":
        raise AuditViolation("bad SOI")
    pos = 2
    eoi = data.rfind(b"\xff\xd9")
    if eoi == -1 or eoi + 2 != len(data):
        raise AuditViolation("must end with exactly one EOI (no trailing data)")
    allowed_sof = set(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}
    while pos < eoi:
        if data[pos] != 0xFF:
            raise AuditViolation(f"expected marker at offset {pos}")
        m = data[pos + 1]
        if m == 0xDA:  # SOS — entropy follows to EOI
            if pos + 4 > len(data):
                raise AuditViolation("truncated SOS")
            (seglen,) = struct.unpack(">H", data[pos + 2 : pos + 4])
            entropy_start = pos + 2 + seglen
            if entropy_start > eoi:
                raise AuditViolation("SOS segment overruns")
            i = entropy_start
            while i < eoi - 1:
                if data[i] == 0xFF:
                    nxt = data[i + 1]
                    if not (nxt == 0x00 or 0xD0 <= nxt <= 0xD7):
                        raise AuditViolation(
                            f"unexpected marker 0x{nxt:02x} inside entropy data"
                        )
                    i += 2
                else:
                    i += 1
            return  # EOI already verified at exact end
        if pos + 4 > len(data):
            raise AuditViolation("truncated segment header")
        (seglen,) = struct.unpack(">H", data[pos + 2 : pos + 4])
        if seglen < 2 or pos + 2 + seglen > len(data):
            raise AuditViolation(f"segment 0x{m:02x} malformed length")
        payload = data[pos + 4 : pos + 2 + seglen]
        if m == 0xFE:
            raise AuditViolation("COM segment present (never written by us)")
        elif m == 0xE0:  # APP0 JFIF
            pass
        elif m == 0xE1:
            if not exp.get("expect_exif") or not payload.startswith(b"Exif\x00\x00"):
                raise AuditViolation("unexpected APP1 (only vetted Exif allowed)")
        elif m == 0xE2:
            if not exp.get("expect_icc") or not payload.startswith(b"ICC_PROFILE\x00"):
                raise AuditViolation("unexpected APP2 (only vetted ICC allowed)")
        elif 0xE3 <= m <= 0xEF:
            raise AuditViolation(f"APP{m - 0xE0} segment present (never written by us)")
        elif m in (0xDB, 0xC4) or m in allowed_sof:
            pass  # DQT / DHT / SOFn
        else:
            raise AuditViolation(f"unexpected marker 0x{m:02x}")
        pos += 2 + seglen


_AUDITORS = {
    "PNG": _audit_png,
    "JPEG": _audit_jpeg,
}


def _audit_gif(data: bytes, exp: dict) -> None:
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        raise AuditViolation("bad GIF signature")
    if len(data) < 14:
        raise AuditViolation("truncated logical screen descriptor")
    lsd_packed = data[10]
    pos = 13
    if lsd_packed & 0x80:  # global color table
        pos += 3 * (2 ** ((lsd_packed & 0x07) + 1))
    saw_image = False
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:  # trailer
            if pos + 1 != len(data):
                raise AuditViolation("trailing data after GIF trailer")
            if not saw_image:
                raise AuditViolation("no image data")
            return
        elif block == 0x21:  # extension
            if pos + 2 > len(data):
                raise AuditViolation("truncated extension")
            label = data[pos + 1]
            if label == 0xFE:
                raise AuditViolation("comment extension present (never written by us)")
            if label == 0x01:
                raise AuditViolation("plain-text extension present (never written by us)")
            if label not in (0xF9, 0xFF):
                raise AuditViolation(f"unknown extension 0x{label:02x}")
            if label == 0xFF:
                # only the NETSCAPE loop extension is expected
                if data[pos + 2 : pos + 3] != b"\x0b" or data[pos + 3 : pos + 14] != b"NETSCAPE2.0":
                    raise AuditViolation("unexpected application extension")
            pos += 2
            while True:  # sub-blocks
                if pos >= len(data):
                    raise AuditViolation("truncated extension sub-blocks")
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                pos += size
        elif block == 0x2C:  # image descriptor
            saw_image = True
            if pos + 10 > len(data):
                raise AuditViolation("truncated image descriptor")
            packed = data[pos + 9]
            pos += 10
            if packed & 0x80:  # local color table
                pos += 3 * (2 ** ((packed & 0x07) + 1))
            if pos >= len(data):
                raise AuditViolation("missing LZW stream")
            pos += 1  # LZW min code size
            while True:  # sub-blocks
                if pos >= len(data):
                    raise AuditViolation("truncated image sub-blocks")
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                pos += size
        else:
            raise AuditViolation(f"unknown block 0x{block:02x}")
    raise AuditViolation("missing GIF trailer")


def _audit_bmp(data: bytes, exp: dict) -> None:
    if data[:2] != b"BM":
        raise AuditViolation("bad BMP signature")
    if len(data) < 26:
        raise AuditViolation("truncated BMP header")
    declared = int.from_bytes(data[2:6], "little")
    if declared != len(data):
        raise AuditViolation(f"BMP declares {declared} bytes but file is {len(data)}")
    offset = int.from_bytes(data[10:14], "little")
    dib = int.from_bytes(data[14:18], "little")
    if dib not in (12, 16, 40, 52, 56, 64, 108, 124):
        raise AuditViolation(f"unexpected DIB header size {dib}")
    if offset >= len(data) or offset < 14 + (dib if dib != 12 else 12):
        raise AuditViolation("pixel offset out of bounds")


def webp_chunks(data: bytes):
    """Yield (fourcc, payload) for each RIFF chunk after the WEBP header."""
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise AuditViolation("bad RIFF/WEBP header")
    pos = 12
    while pos + 8 <= len(data):
        fourcc = data[pos : pos + 4]
        (sz,) = struct.unpack("<I", data[pos + 4 : pos + 8])
        if pos + 8 + sz > len(data):
            raise AuditViolation(f"chunk {fourcc!r} overruns file")
        yield fourcc, data[pos + 8 : pos + 8 + sz]
        pos += 8 + sz + (sz & 1)
    if pos != len(data):
        raise AuditViolation("trailing data after last RIFF chunk")


def _audit_webp(data: bytes, exp: dict) -> None:
    allowed = {b"VP8X", b"ANIM", b"ANMF", b"VP8 ", b"VP8L", b"ALPH"}
    if exp.get("expect_exif"):
        allowed.add(b"EXIF")
    if exp.get("expect_icc"):
        allowed.add(b"ICCP")
    saw_frame = False
    for fourcc, _payload in webp_chunks(data):
        if fourcc not in allowed:
            raise AuditViolation(f"unexpected RIFF chunk {fourcc!r}")
        if fourcc in (b"VP8 ", b"VP8L", b"ANMF"):
            saw_frame = True
    if not saw_frame:
        raise AuditViolation("no frame data")


_AUDITORS["GIF"] = _audit_gif
_AUDITORS["BMP"] = _audit_bmp
_AUDITORS["WEBP"] = _audit_webp
