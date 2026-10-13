#!/usr/bin/env python3
"""Fill the real-world test corpus (tests/corpus/) with hostile samples.

Two sources, two subcommands:

  generate   Craft hostile inputs locally from Pillow + byte surgery
             (webshells, smuggle chunks, bombs, polyglots, EICAR trailer).
             Written to <out>/crafted/.

  download   Fetch genuinely malicious published samples — ImageTragick
             PoCs, Pillow regression crashers/bombs, CVE-2023-4863 WebP —
             each pinned by SHA-256; a hash mismatch aborts the download.
             Written to <out>/downloaded/ with a SOURCES.md provenance
             file.

Both modes merge per-file expectations into tests/corpus_manifest.json
(preserving unrelated entries) and then — unless --skip-verify — run the
sandboxed sanitizer over every file they added, comparing the observed
outcome with the pinned expectation. Verification failure exits 1.

The corpus directory is gitignored; sample bytes never enter the repo.

Usage:
    .venv/bin/python scripts/fill_corpus.py generate
    .venv/bin/python scripts/fill_corpus.py download
    .venv/bin/python scripts/fill_corpus.py all [--force] [--only bomb]

Safety: files are only ever written and read as bytes, then decoded
inside the sanitizer's rlimit'ed worker. Nothing here executes, renders,
or otherwise interprets a sample.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from imgfactory import (  # noqa: E402
    make_gif,
    make_jpeg,
    make_png,
    patch_png_ihdr,
    png_insert_chunk,
)

CORPUS_DEFAULT = ROOT / "tests" / "corpus"
MANIFEST_PATH = ROOT / "tests" / "corpus_manifest.json"

DOWNLOAD_TIMEOUT = 30

EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
PHP_SHELL = b"<?php system($_GET['c']); ?>"

# ---------------------------------------------------------------------------
# generate: crafted samples (name -> builder, expectation, description)
# ---------------------------------------------------------------------------


def _gif_with_comment(payload: bytes) -> bytes:
    """Animated GIF with a hostile comment extension before the trailer."""
    data = make_gif()
    assert data.endswith(b"\x3b")
    assert len(payload) < 255
    comment = b"\x21\xfe" + bytes([len(payload)]) + payload + b"\x00"
    return data[:-1] + comment + b"\x3b"


def _pixel_bomb_png() -> bytes:
    """Genuine 81 MP solid-color PNG: tiny on disk, over the 50 MP budget."""
    from PIL import Image

    im = Image.new("P", (9000, 9000))
    im.putpalette([200, 30, 40] + [0, 0, 0] * 255)
    buf = io.BytesIO()
    im.save(buf, "PNG", optimize=True)
    return buf.getvalue()


GENERATED: list[tuple[str, bytes, str, str]] = []


def _generated() -> list[tuple[str, bytes, str, str]]:
    if GENERATED:
        return GENERATED
    raw_profile = b"Raw profile type exif\x00" + b"ZW5jb2RlZCBldmlsIGV4aWYK"
    GENERATED.extend(
        [
            (
                "crafted/benign-photo.jpg",
                make_jpeg(size=(64, 48)),
                "clean",
                "baseline: ordinary JPEG must pass through",
            ),
            (
                "crafted/benign-graphic.png",
                make_png(size=(64, 48)),
                "clean",
                "baseline: ordinary PNG must pass through",
            ),
            (
                "crafted/webshell-trailer-jpeg.jpg",
                make_jpeg() + PHP_SHELL,
                "clean",
                "PHP webshell appended after JPEG EOI — payload must vanish",
            ),
            (
                "crafted/eicar-trailer-jpeg.jpg",
                make_jpeg() + EICAR,
                "clean",
                "EICAR antivirus test string as payload — harmless by design",
            ),
            (
                "crafted/php-after-iend.png",
                make_png() + PHP_SHELL,
                "clean",
                "PHP payload appended after PNG IEND",
            ),
            (
                "crafted/smuggle-raw-profile.png",
                png_insert_chunk(make_png(), b"tEXt", raw_profile),
                "clean",
                'ImageMagick "Raw profile type exif" smuggle chunk',
            ),
            (
                "crafted/xmp-jpeg.jpg",
                make_jpeg(xmp=b"<x:xmpmeta><rdf:RDF>evil</rdf:RDF></x:xmpmeta>"),
                "clean",
                "XMP packet riding in a JPEG APP1",
            ),
            (
                "crafted/mpo-concat.jpg",
                make_jpeg(size=(4, 4)) + make_jpeg(size=(6, 2), color=(9, 9, 9)),
                "clean",
                "second JPEG concatenated (MPO-style second image)",
            ),
            (
                "crafted/gif-comment-webshell.gif",
                _gif_with_comment(PHP_SHELL),
                "clean",
                "webshell in a GIF comment extension",
            ),
            (
                "crafted/wrong-extension-gif.png",
                make_gif(),
                "clean",
                "GIF bytes lying about their extension — content wins",
            ),
            (
                "crafted/dimension-bomb.png",
                patch_png_ihdr(make_png(), 100000, 100000),
                "LimitExceeded",
                "IHDR claims 100000x100000 with tiny data behind it",
            ),
            (
                "crafted/pixel-bomb.png",
                _pixel_bomb_png(),
                "LimitExceeded",
                "81 MP solid-color PNG: small file, over-budget pixels",
            ),
            (
                "crafted/truncated-garbage.png",
                b"\x89PNG\r\n\x1a\nGARBAGE",
                "Undecodable",
                "valid magic, nothing behind it",
            ),
        ]
    )
    return GENERATED


# ---------------------------------------------------------------------------
# download: pinned remote samples (path -> url, sha256, expectation, source)
# ---------------------------------------------------------------------------

_PILLOW = "https://raw.githubusercontent.com/python-pillow/Pillow/main/Tests/images"
_ITRAG = "https://raw.githubusercontent.com/ImageTragick/PoCs/master"
_WEBP = "https://raw.githubusercontent.com/mistymntncop/CVE-2023-4863/main"

DOWNLOADS: list[tuple[str, str, str, str, str]] = [
    (
        "downloaded/imagetragick-rce1.jpg",
        f"{_ITRAG}/rce1.jpg",
        "7b47712feeb75eb08fc3860c7affdf985e5b08554000126b9319084db58d14cc",
        "UnsupportedFormat",
        "ImageTragick PoC: MVG script named .jpg (SSRF/RCE delegate abuse)",
    ),
    (
        "downloaded/imagetragick-msl.jpg",
        f"{_ITRAG}/msl.jpg",
        "a38e86ade364824c778fac915226fbf3e2ffdca9e392aa05e2f5385573dc2a5e",
        "UnsupportedFormat",
        "ImageTragick PoC: MSL (scripting) payload named .jpg",
    ),
    (
        "downloaded/imagetragick-test.png",
        f"{_ITRAG}/test.png",
        "049194ec4b30481c602d270c7dd93870e070417ff5adf12432e91752eab4343a",
        "clean",
        "ImageTragick PoC companion image",
    ),
    (
        "downloaded/pillow-decompression-bomb.gif",
        f"{_PILLOW}/decompression_bomb.gif",
        "7357284ef3ce2f16a3eb5e6f64ba9eeaded1487661b36ed6ac73476bce24a38e",
        "LimitExceeded",
        "Pillow regression sample: 44-byte GIF that explodes on decode",
    ),
    (
        "downloaded/pillow-decompression-bomb-extents.gif",
        f"{_PILLOW}/decompression_bomb_extents.gif",
        "e6c8a34e09874ac1363facf01821cfaed3f494fa596f0b578fae87dac562ee79",
        "SandboxCrash",
        "Pillow regression sample: GIF crasher — kills the sandbox worker",
    ),
    (
        "downloaded/pillow-broken.png",
        f"{_PILLOW}/broken.png",
        "6c61140490655f0a5c878c99c9216c1748e5838f6841c77f8492a55a3242483f",
        "Undecodable",
        "Pillow regression sample: structurally broken PNG",
    ),
    (
        "downloaded/pillow-broken-data-stream.png",
        f"{_PILLOW}/broken_data_stream.png",
        "1b6dfa9df2a80fdf764cd51f3bb310928d08bc050a31d09f9c22bdfbae99824d",
        "Undecodable",
        "Pillow regression sample: corrupt PNG data stream",
    ),
    (
        "downloaded/pillow-truncated-jpeg.jpg",
        f"{_PILLOW}/truncated_jpeg.jpg",
        "9a83b18bfa4b7fbe1f89f4bec096a5782f2d649c707c5693fcce995d13141b39",
        "Undecodable",
        "Pillow regression sample: truncated JPEG scan",
    ),
    (
        "downloaded/pillow-invalid-exif.jpg",
        f"{_PILLOW}/invalid-exif.jpg",
        "29d511287ad90028ab19e5c6651a25d4e17220549fca0d0f155eb3dd0bbbde02",
        "clean",
        "Pillow regression sample: invalid EXIF dropped, pixels survive",
    ),
    (
        "downloaded/pillow-hopper-rle8-overflow.bmp",
        f"{_PILLOW}/hopper_rle8_row_overflow.bmp",
        "c1787678ec8b643a9f5cea7fa6e8cd03e5d2e82f04285bbac2fb18734a489432",
        "clean",
        "Pillow regression sample: RLE8 BMP row overflow, benign pixels",
    ),
    (
        "downloaded/webp-cve-2023-4863-bad.webp",
        f"{_WEBP}/bad.webp",
        "34f3ca760640a63c321d98267a029e8c918f434ca9a30dbf6fe1adab65d63a63",
        "Undecodable",
        "CVE-2023-4863 crafted WebP (lossless Huffman heap overflow PoC)",
    ),
    (
        "downloaded/webp-cve-2023-4863-nso.webp",
        f"{_WEBP}/nso.webp",
        "eab21bc833efca382d5a3fc7e449a240dc91dfb90de9d423aff73d42baba3a46",
        "Undecodable",
        "CVE-2023-4863 second crafted WebP",
    ),
]


# ---------------------------------------------------------------------------
# corpus + manifest plumbing
# ---------------------------------------------------------------------------


def write_sample(out_root: Path, rel: str, data: bytes, force: bool) -> str:
    """Write one sample; returns 'wrote', 'kept' (already present) or raises."""
    path = out_root / rel
    if path.exists() and not force:
        if path.read_bytes() == data:
            return "kept"
        raise SystemExit(
            f"refusing to overwrite existing {path} (differs; use --force)"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return "wrote"


def update_manifest(entries: dict[str, str]) -> None:
    raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    files = raw.get("files", {})
    files.update(entries)
    merged = {"_doc": raw.get("_doc", ""), "files": dict(sorted(files.items()))}
    MANIFEST_PATH.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "image-sanitizer-corpus"})
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as resp:
        return resp.read()


def verify(out_root: Path, entries: dict[str, str]) -> int:
    """Run the sandboxed sanitizer over each entry; report mismatches."""
    from image_sanitizer import RejectionError, sanitize

    failures = 0
    print("\nverifying against the sanitizer (sandboxed)...")
    for rel in sorted(entries):
        expected = entries[rel]
        try:
            result = sanitize((out_root / rel).read_bytes())
            observed = "clean"
            extra = f"format={result.report.input_format}"
        except RejectionError as e:
            observed = type(e).__name__
            extra = str(e.detail)[:40]
        ok = observed == expected
        failures += not ok
        mark = "ok " if ok else "MISMATCH"
        print(f"  [{mark}] {rel:48s} expect={expected:18s} got={observed:18s} {extra}")
    return failures


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------


def cmd_generate(out_root: Path, force: bool, only: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    print("crafting samples...")
    for rel, data, expectation, _desc in _generated():
        if only and only not in rel:
            continue
        status = write_sample(out_root, rel, data, force)
        entries[rel] = expectation
        print(f"  [{status:5s}] {rel}")
    return entries


def cmd_download(out_root: Path, force: bool, only: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    provenance: list[str] = []
    print("downloading pinned samples...")
    for rel, url, sha256, expectation, desc in DOWNLOADS:
        if only and only not in rel:
            continue
        path = out_root / rel
        if path.exists() and not force:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest == sha256:
                entries[rel] = expectation
                print(f"  [kept  ] {rel}")
                continue
            raise SystemExit(
                f"{path} exists with unexpected content (use --force to replace)"
            )
        data = fetch(url)
        digest = hashlib.sha256(data).hexdigest()
        if digest != sha256:
            raise SystemExit(
                f"SHA-256 mismatch for {url}\n  expected {sha256}\n  got      "
                f"{digest}\n  upstream changed — refusing; update the pin "
                f"deliberately if the new content is wanted."
            )
        status = write_sample(out_root, rel, data, force)
        entries[rel] = expectation
        print(f"  [{status:5s}] {rel}")
    if entries:
        provenance.append("# Downloaded corpus provenance\n")
        for rel, url, sha256, _exp, desc in DOWNLOADS:
            if rel in entries:
                provenance.append(f"- `{rel}` — {desc}\n  - {url}\n  - sha256:{sha256}\n")
        (out_root / "downloaded" / "SOURCES.md").write_text(
            "\n".join(provenance), encoding="utf-8"
        )
    return entries


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "mode", choices=["generate", "download", "all"], help="corpus fill mode"
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=CORPUS_DEFAULT,
        help=f"corpus root (default: {CORPUS_DEFAULT})",
    )
    ap.add_argument("--force", action="store_true", help="overwrite existing files")
    ap.add_argument(
        "--only", default="", help="only touch samples whose path contains SUBSTR"
    )
    ap.add_argument(
        "--skip-verify",
        action="store_true",
        help="do not run the sanitizer over the samples afterwards",
    )
    args = ap.parse_args(argv)

    entries: dict[str, str] = {}
    if args.mode in ("generate", "all"):
        entries.update(cmd_generate(args.out, args.force, args.only))
    if args.mode in ("download", "all"):
        entries.update(cmd_download(args.out, args.force, args.only))

    if not entries:
        print("nothing selected — corpus unchanged")
        return 0

    update_manifest(entries)
    print(f"\nmanifest updated: {MANIFEST_PATH.relative_to(ROOT)}")

    if args.skip_verify:
        print("verification skipped")
        return 0
    failures = verify(args.out, entries)
    if failures:
        print(f"\n{failures} mismatch(es) — fix the pins or the product, not the test")
        return 1
    print(f"\ncorpus ready: {len(entries)} sample(s) under {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
