"""Builders for crafted test inputs — the adversarial corpus generators.

Everything is built from Pillow outputs plus raw byte surgery so the corpus
is reproducible and self-documenting.
"""

from __future__ import annotations

import io
import struct

from PIL import Image


def make_png(size=(8, 6), color=(200, 30, 40), mode="RGB") -> bytes:
    im = Image.new(mode, size, color)
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def make_bmp(size=(8, 6), color=(200, 30, 40)) -> bytes:
    im = Image.new("RGB", size, color)
    buf = io.BytesIO()
    im.save(buf, "BMP")
    return buf.getvalue()


def make_tiff(size=(8, 6), color=(200, 30, 40), mode="RGB", pages=1) -> bytes:
    """Little-endian uncompressed TIFF; ``pages > 1`` makes it multi-page."""
    ims = [Image.new(mode, size, color) for _ in range(pages)]
    buf = io.BytesIO()
    kw: dict = {"compression": "raw"}
    if pages > 1:
        kw.update(save_all=True, append_images=ims[1:])
    ims[0].save(buf, "TIFF", **kw)
    return buf.getvalue()


def make_tiff_be(pixels: bytes = b"\x00\x40\x80\xff", size=(2, 2)) -> bytes:
    """Hand-built big-endian 8-bit grayscale TIFF (Pillow only writes ``II`` for it)."""
    w, h = size
    assert len(pixels) == w * h
    entries = [
        (256, 3, w),  # ImageWidth
        (257, 3, h),  # ImageLength
        (258, 3, 8),  # BitsPerSample
        (259, 3, 1),  # Compression: none
        (262, 3, 1),  # Photometric: BlackIsZero
        (273, 4, 8 + 2 + 9 * 12 + 4),  # StripOffsets
        (277, 3, 1),  # SamplesPerPixel
        (278, 3, h),  # RowsPerStrip
        (279, 4, len(pixels)),  # StripByteCounts
    ]
    ifd = struct.pack(">H", len(entries))
    for tag, typ, val in entries:
        ifd += struct.pack(">HHI", tag, typ, 1)
        ifd += struct.pack(">H2x", val) if typ == 3 else struct.pack(">I", val)
    return b"MM\x00*" + struct.pack(">I", 8) + ifd + struct.pack(">I", 0) + pixels


def make_jpeg(size=(8, 6), color=(200, 30, 40), quality=95, **save_kwargs) -> bytes:
    im = Image.new("RGB", size, color)
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=quality, **save_kwargs)
    return buf.getvalue()


def make_gif(frames=((200, 30, 40), (30, 200, 40)), size=(8, 6), durations=None) -> bytes:
    """Animated GIF where frame N is a solid P-mode image of color N."""
    ims = []
    for color in frames:
        pal = Image.new("P", size)
        pal.putpalette(list(color) + [0, 0, 0] * 255)
        ims.append(pal)
    buf = io.BytesIO()
    kw: dict = {"save_all": True, "loop": 0}
    if durations:
        kw["duration"] = durations
    ims[0].save(buf, "GIF", append_images=ims[1:], **kw)
    return buf.getvalue()


def patch_png_ihdr(data: bytes, width: int, height: int) -> bytes:
    """Rewrite the IHDR dimensions without touching anything else."""
    ba = bytearray(data)
    struct.pack_into(">II", ba, 16, width, height)
    # fix the IHDR CRC
    import zlib

    body = bytes(ba[12:29])  # type + 13-byte payload
    struct.pack_into(">I", ba, 29, zlib.crc32(body) & 0xFFFFFFFF)
    return bytes(ba)


def png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    """Parse a PNG into (chunk_type, payload) pairs for assertions."""
    out = []
    pos = 8
    while pos + 8 <= len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        ctype = data[pos + 4 : pos + 8]
        out.append((ctype, data[pos + 8 : pos + 8 + length]))
        pos += 12 + length
    return out


def png_find_chunk(data: bytes, ctype: bytes) -> bytes | None:
    for t, payload in png_chunks(data):
        if t == ctype:
            return payload
    return None


def png_insert_chunk(data: bytes, ctype: bytes, payload: bytes) -> bytes:
    """Insert a chunk right before IEND."""
    import zlib

    chunk = struct.pack(">I", len(payload)) + ctype + payload
    chunk += struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF)
    idx = data.rfind(b"IEND") - 4
    return data[:idx] + chunk + data[idx:]


def png_append_after_iend(data: bytes, suffix: bytes) -> bytes:
    return data + suffix
