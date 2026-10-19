"""TIFF support: single-page, uncompressed output, both byte orders accepted.

Seam: public `sanitize()`; expectations computed by independent Pillow
decodes of the raw input.
"""

from __future__ import annotations

import io
import struct

import pytest
from PIL import Image, ImageCms

from pillow_wash import LimitExceeded, RejectionReason, sanitize
from pillow_wash.audit import AuditViolation, audit

from imgfactory import make_png, make_tiff, make_tiff_be


def test_tiff_roundtrips_pixel_exact() -> None:
    src = make_tiff(size=(9, 5))

    result = sanitize(src, isolation="none")

    assert result.data[:4] == b"II*\x00"
    a = Image.open(io.BytesIO(src)).convert("RGB")
    b = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert a.tobytes() == b.tobytes()
    assert result.report.input_format == result.report.output_format == "TIFF"


def test_multipage_tiff_is_rejected() -> None:
    src = make_tiff(pages=2)

    with pytest.raises(LimitExceeded) as ei:
        sanitize(src, isolation="none")

    assert ei.value.reason is RejectionReason.LIMIT_EXCEEDED
    assert "multi-page" in ei.value.detail


def test_big_endian_tiff_is_accepted_and_output_is_little_endian() -> None:
    src = make_tiff_be()
    assert src[:4] == b"MM\x00*"

    result = sanitize(src, isolation="none")

    assert result.data[:4] == b"II*\x00"
    a = Image.open(io.BytesIO(src))
    b = Image.open(io.BytesIO(result.data))
    assert a.tobytes() == b.tobytes() == b"\x00\x40\x80\xff"


def test_png_input_can_be_converted_to_tiff() -> None:
    src = make_png()

    result = sanitize(src, output_format="tiff", isolation="none")

    assert result.data[:4] == b"II*\x00"
    a = Image.open(io.BytesIO(src)).convert("RGB")
    b = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert a.tobytes() == b.tobytes()


def test_tiff_input_can_be_converted_to_png() -> None:
    src = make_tiff()

    result = sanitize(src, output_format="png", isolation="none")

    assert result.data[:8] == b"\x89PNG\r\n\x1a\n"
    a = Image.open(io.BytesIO(src)).convert("RGB")
    b = Image.open(io.BytesIO(result.data)).convert("RGB")
    assert a.tobytes() == b.tobytes()


def test_declared_format_tif_resolves_without_mismatch() -> None:
    result = sanitize(make_tiff(), declared_format="tif", isolation="none")

    assert result.report.declared_format == "TIFF"
    assert result.report.mismatch is False


# ------------------------------------------------------------------ audit ----

TS = "2023:01:02 03:04:05"
TS2 = "2023:01:02 03:04:06"
BASELINE_TAGS = {256, 257, 258, 259, 262, 273, 277, 278, 279, 284, 320, 338, 339}
LEAKY = {
    270: b"DescriptionLeak",
    305: b"SoftwareLeak",
    700: b"<x:xmpmeta>XmpLeak",
    33723: b"IptcLeak!",
    34377: b"PhotoshopLeak",
}


def srgb_profile() -> bytes:
    return ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()


def rich_exif(orientation: int | None = None) -> Image.Exif:
    """EXIF carrying whitelisted timestamps plus every leaky tag we must drop."""
    ex = Image.Exif()
    ex[306] = TS
    for tag, value in LEAKY.items():
        ex[tag] = value.decode() if tag in (270, 305) else value
    if orientation:
        ex[274] = orientation
    sub = ex.get_ifd(0x8769)
    sub[36867] = TS2
    sub[37510] = "UserCommentLeak"
    gps = ex.get_ifd(0x8825)
    gps[1] = "N"
    gps[2] = (42.0, 0.0, 0.0)
    return ex


def rich_tiff(mode="RGB", size=(7, 5), icc=None, orientation=None, **kw) -> bytes:
    im = Image.new(mode, size)
    if mode == "P":
        im.putpalette([(i * 5) % 256 for i in range(768)])
    buf = io.BytesIO()
    im.save(buf, "TIFF", compression="raw", exif=rich_exif(orientation).tobytes(), icc_profile=icc, **kw)
    return buf.getvalue()


def sanitized(mode="RGB", icc=False, exif=False) -> bytes:
    if exif or icc:
        src = rich_tiff(mode, icc=srgb_profile() if icc else None)
    else:
        src = make_tiff(mode=mode, color=0) if mode != "P" else make_tiff_palette()
    return sanitize(src, isolation="none").data


def make_tiff_palette() -> bytes:
    im = Image.new("P", (7, 5))
    im.putpalette([(i * 5) % 256 for i in range(768)])
    buf = io.BytesIO()
    im.save(buf, "TIFF", compression="raw")
    return buf.getvalue()


def ifd_entries(data: bytes) -> dict[int, tuple[int, int, int, int]]:
    """tag -> (entry_pos, type, count, value_field_pos) for a little-endian IFD0."""
    (off,) = struct.unpack("<I", data[4:8])
    (n,) = struct.unpack("<H", data[off : off + 2])
    out = {}
    for i in range(n):
        pos = off + 2 + 12 * i
        tag, typ, count = struct.unpack("<HHI", data[pos : pos + 8])
        out[tag] = (pos, typ, count, pos + 8)
    return out


def poke(data: bytes, pos: int, fmt: str, *values) -> bytes:
    ba = bytearray(data)
    struct.pack_into(fmt, ba, pos, *values)
    return bytes(ba)


def next_ifd_pos(data: bytes) -> int:
    (off,) = struct.unpack("<I", data[4:8])
    (n,) = struct.unpack("<H", data[off : off + 2])
    return off + 2 + 12 * n


def exif_subifd_entries(data: bytes) -> dict[int, int]:
    pos, _, _, vpos = ifd_entries(data)[34665]
    (off,) = struct.unpack("<I", data[vpos : vpos + 4])
    (n,) = struct.unpack("<H", data[off : off + 2])
    return {
        struct.unpack("<H", data[off + 2 + 12 * i : off + 4 + 12 * i])[0]: off + 2 + 12 * i
        for i in range(n)
    }


def two_strip_tiff(bo: str = "<") -> bytes:
    """Hand-built 4x2 grayscale TIFF with two one-row strips (out-of-line offsets/counts)."""
    w, h = 4, 2
    n = 9
    ifd_size = 2 + 12 * n + 4
    off_arr = 8 + ifd_size
    cnt_arr = off_arr + 8
    data_start = cnt_arr + 8
    entries = [
        (256, 3, 1, w), (257, 3, 1, h), (258, 3, 1, 8), (259, 3, 1, 1), (262, 3, 1, 1),
        (273, 4, 2, off_arr), (278, 3, 1, 1), (279, 4, 2, cnt_arr), (284, 3, 1, 1),
    ]
    ifd = struct.pack(bo + "H", n)
    for tag, typ, count, val in entries:
        ifd += struct.pack(bo + "HHI", tag, typ, count)
        ifd += struct.pack(bo + "H2x", val) if typ == 3 else struct.pack(bo + "I", val)
    ifd += struct.pack(bo + "I", 0)
    body = struct.pack(bo + "2I", data_start, data_start + 4) + struct.pack(bo + "2I", 4, 4)
    magic = b"II*\x00" if bo == "<" else b"MM\x00*"
    return magic + struct.pack(bo + "I", 8) + ifd + body + b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08"


@pytest.mark.parametrize("mode", ["L", "RGB", "RGBA", "P", "1", "I;16", "CMYK"])
@pytest.mark.parametrize("meta", [False, True], ids=["bare", "icc+exif"])
def test_real_sanitized_output_passes_audit(mode, meta) -> None:
    data = sanitized(mode, icc=meta, exif=meta)

    audit(data, "TIFF", expect_icc=meta, expect_exif=meta)


@pytest.mark.parametrize("size", [(1, 1), (9, 3), (300, 200)])
def test_real_output_passes_audit_for_odd_sizes(size) -> None:
    data = sanitize(make_tiff(size=size, mode="L", color=7), isolation="none").data

    audit(data, "TIFF")


def test_pillow_word_alignment_padding_after_odd_icc_is_accepted() -> None:
    # Pillow pads odd-length out-of-line values to a word boundary with one zero byte.
    icc = (srgb_profile() + b"\x00")[:587]
    buf = io.BytesIO()
    Image.new("L", (7, 5)).save(buf, "TIFF", compression="raw", icc_profile=icc)
    data = buf.getvalue()
    pos, _, count, vpos = ifd_entries(data)[34675]
    (voff,) = struct.unpack("<I", data[vpos : vpos + 4])
    pad_pos = voff + count
    assert data[pad_pos] == 0 and pad_pos + 1 == struct.unpack("<I", data[ifd_entries(data)[273][3] :][:4])[0]

    audit(data, "TIFF", expect_icc=True)

    with pytest.raises(AuditViolation):
        audit(poke(data, pad_pos, "B", 1), "TIFF", expect_icc=True)


@pytest.mark.parametrize("bo", ["<", ">"])
def test_multi_strip_tiff_with_out_of_line_arrays_passes(bo) -> None:
    audit(two_strip_tiff(bo), "TIFF")


def test_multi_strip_out_of_bounds_second_strip_is_rejected() -> None:
    data = two_strip_tiff()
    cnt_pos = ifd_entries(data)[279][3]
    (cnt_off,) = struct.unpack("<I", data[cnt_pos : cnt_pos + 4])

    with pytest.raises(AuditViolation, match="strip"):
        audit(poke(data, cnt_off + 4, "<I", 5), "TIFF")


def test_multi_strip_gap_between_strips_is_rejected() -> None:
    data = two_strip_tiff()
    off_pos = ifd_entries(data)[273][3]
    (off_off,) = struct.unpack("<I", data[off_pos : off_pos + 4])
    (second,) = struct.unpack("<I", data[off_off + 4 : off_off + 8])
    # shift the second strip one byte later and pad the file: first-strip end..second-strip start is a gap
    patched = poke(data, off_off + 4, "<I", second + 1) + b"\x00"

    with pytest.raises(AuditViolation, match="uncovered"):
        audit(patched, "TIFF")


def test_trailing_bytes_are_rejected() -> None:
    with pytest.raises(AuditViolation, match="uncovered|trailing"):
        audit(sanitized() + b"<?php ?>", "TIFF")


def test_second_ifd_is_rejected() -> None:
    data = sanitized()
    patched = poke(data, next_ifd_pos(data), "<I", 8)

    with pytest.raises(AuditViolation, match="IFD"):
        audit(patched, "TIFF")


@pytest.mark.parametrize("tag", [270, 305, 700, 33723, 34377, 34853, 282, 274])
def test_unexpected_tag_is_rejected(tag) -> None:
    data = sanitized()
    patched = poke(data, ifd_entries(data)[284][0], "<H", tag)

    with pytest.raises(AuditViolation, match="unexpected tag"):
        audit(patched, "TIFF")


def test_compression_other_than_raw_is_rejected() -> None:
    data = sanitized()
    patched = poke(data, ifd_entries(data)[259][3], "<H", 5)

    with pytest.raises(AuditViolation, match="compression"):
        audit(patched, "TIFF")


@pytest.mark.parametrize("tag", [273, 279])
def test_strip_out_of_bounds_is_rejected(tag) -> None:
    data = sanitized()
    patched = poke(data, ifd_entries(data)[tag][3], "<I", len(data))

    with pytest.raises(AuditViolation, match="strip"):
        audit(patched, "TIFF")


def test_strip_overlapping_the_header_is_rejected() -> None:
    data = sanitized()

    with pytest.raises(AuditViolation):
        audit(poke(data, ifd_entries(data)[273][3], "<I", 0), "TIFF")


def test_datetime_without_expect_exif_is_rejected() -> None:
    data = sanitized(exif=True)

    audit(data, "TIFF", expect_exif=True)
    with pytest.raises(AuditViolation, match="unexpected tag 306"):
        audit(data, "TIFF", expect_exif=False)


def test_exif_pointer_without_expect_exif_is_rejected() -> None:
    ex = Image.Exif()
    ex.get_ifd(0x8769)[36867] = TS2  # no tag 306: the Exif pointer is the only exif structure
    buf = io.BytesIO()
    Image.new("L", (4, 3)).save(buf, "TIFF", compression="raw", exif=ex.tobytes())
    data = buf.getvalue()
    assert 34665 in ifd_entries(data) and 306 not in ifd_entries(data)

    audit(data, "TIFF", expect_exif=True)
    with pytest.raises(AuditViolation, match="unexpected tag 34665"):
        audit(data, "TIFF", expect_exif=False)


def test_icc_without_expect_icc_is_rejected() -> None:
    data = sanitized(icc=True)

    audit(data, "TIFF", expect_icc=True, expect_exif=True)
    with pytest.raises(AuditViolation, match="unexpected tag 34675"):
        audit(data, "TIFF", expect_icc=False, expect_exif=True)


def test_exif_subifd_with_other_tag_is_rejected() -> None:
    data = sanitized(exif=True)
    patched = poke(data, exif_subifd_entries(data)[36867], "<H", 37510)

    with pytest.raises(AuditViolation, match="Exif"):
        audit(patched, "TIFF", expect_exif=True)


def test_exif_subifd_next_pointer_must_be_zero() -> None:
    data = sanitized(exif=True)
    pos = min(exif_subifd_entries(data).values()) + 12
    with pytest.raises(AuditViolation):
        audit(poke(data, pos, "<I", 8), "TIFF", expect_exif=True)


@pytest.mark.parametrize(
    "data",
    [b"", b"II*\x00", b"XX*\x00\x08\x00\x00\x00", b"II+\x00\x08\x00\x00\x00", b"MM\x00*\x00\x00\x00\x00"],
    ids=["empty", "short", "bad-order", "bigtiff-magic", "ifd-offset-zero"],
)
def test_bad_header_is_rejected(data) -> None:
    with pytest.raises(AuditViolation):
        audit(data, "TIFF")


def test_hidden_bytes_between_structures_are_rejected() -> None:
    data = sanitized()
    pos = ifd_entries(data)[273][3]
    (off,) = struct.unpack("<I", data[pos : pos + 4])
    # move the strip one byte later and add a byte at the end: original first strip byte is uncovered
    patched = poke(data, pos, "<I", off + 1) + b"\xaa"

    with pytest.raises(AuditViolation, match="uncovered"):
        audit(patched, "TIFF")


def test_nonzero_inline_padding_is_rejected() -> None:
    data = sanitized()
    patched = poke(data, ifd_entries(data)[259][3] + 2, "<H", 0x4141)

    with pytest.raises(AuditViolation):
        audit(patched, "TIFF")


def test_truncated_file_is_rejected() -> None:
    with pytest.raises(AuditViolation):
        audit(sanitized()[:-1], "TIFF")


# -------------------------------------------------------------- end to end ----

def tag_ids(data: bytes) -> set[int]:
    return set(ifd_entries(data))


def test_tiff_drops_leaky_metadata_and_keeps_timestamps_and_icc() -> None:
    prof = srgb_profile()
    src = rich_tiff(icc=prof)
    assert {270, 305, 700, 33723, 34377, 34853} <= tag_ids(src)

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    assert tag_ids(result.data) <= BASELINE_TAGS | {306, 34665, 34675}
    assert {306, 34665, 34675} <= tag_ids(result.data)
    ex = out.getexif()
    assert ex.get(306) == TS
    assert ex.get_ifd(0x8769).get(36867) == TS2
    assert set(ex.get_ifd(0x8769)) == {36867}
    assert out.info.get("icc_profile") == prof
    for secret in (*LEAKY.values(), b"UserCommentLeak"):
        assert secret not in result.data


def test_tiff_without_whitelisted_metadata_has_only_structural_tags() -> None:
    ex = Image.Exif()
    for tag, value in LEAKY.items():
        ex[tag] = value.decode() if tag in (270, 305) else value
    buf = io.BytesIO()
    Image.new("RGB", (6, 4)).save(buf, "TIFF", compression="raw", exif=ex, dpi=(300, 300))

    result = sanitize(buf.getvalue(), isolation="none")

    assert tag_ids(result.data) <= BASELINE_TAGS
    for secret in LEAKY.values():
        assert secret not in result.data


def test_tiff_resolution_tags_are_not_carried_over() -> None:
    buf = io.BytesIO()
    Image.new("RGB", (6, 4)).save(buf, "TIFF", compression="raw", dpi=(300, 300))
    assert {282, 283, 296} <= tag_ids(buf.getvalue())

    result = sanitize(buf.getvalue(), isolation="none")

    assert not {282, 283, 296} & tag_ids(result.data)


def test_tiff_orientation_is_baked_and_tag_dropped() -> None:
    im = Image.new("RGB", (7, 3))
    px = im.load()
    for y in range(3):
        for x in range(7):
            px[x, y] = (x * 30, y * 60, (x + y) * 10)
    buf = io.BytesIO()
    im.save(buf, "TIFF", compression="raw", exif=rich_exif(orientation=6).tobytes())
    src = buf.getvalue()
    assert Image.open(io.BytesIO(src)).getexif().get(274) == 6

    result = sanitize(src, isolation="none")

    out = Image.open(io.BytesIO(result.data))
    expected = im.transpose(Image.Transpose.ROTATE_270)  # orientation 6: rotate 90 deg clockwise
    assert out.size == (3, 7)
    assert out.convert("RGB").tobytes() == expected.tobytes()
    assert 274 not in tag_ids(result.data)
    assert out.getexif().get(274) is None
