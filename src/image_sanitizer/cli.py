"""The CLI: explicit output paths, batch mode, never in-place mutation.

Exit codes: 0 all Clean, 1 at least one Rejection, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .exceptions import RejectionError
from .sanitizer import sanitize

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="image-sanitizer",
        description=(
            "Sanitize untrusted images by whitelist-rebuild: clean pixels, "
            "vetted metadata, nothing inherited from the input."
        ),
    )
    p.add_argument("input", help="input file or directory of images")
    p.add_argument("-o", "--output", required=True, help="output file or directory")
    p.add_argument("--format", dest="format", help="output format override (png/jpeg/gif/webp/bmp)")
    p.add_argument("--json", action="store_true", help="print machine-readable reports")
    p.add_argument("--quiet", action="store_true", help="suppress per-file output")
    p.add_argument("--force", action="store_true", help="allow overwriting an existing output file")
    p.add_argument(
        "--in-process",
        action="store_true",
        help="dev/debug: decode in-process instead of the sandbox worker",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    inp = Path(args.input)
    out = Path(args.output)

    if not inp.exists():
        print(f"error: input does not exist: {inp}", file=sys.stderr)
        return 2

    isolation = "none" if args.in_process else "sandbox"

    if inp.is_dir():
        if out.exists() and not out.is_dir():
            print(f"error: output must be a directory for batch mode: {out}", file=sys.stderr)
            return 2
        out.mkdir(parents=True, exist_ok=True)
        files = sorted(
            f for f in inp.iterdir() if f.is_file()
        )
        if not files:
            print(f"error: no files in input directory: {inp}", file=sys.stderr)
            return 2
        rejected = 0
        for f in files:
            dst = out / f.name
            rc = _sanitize_one(f, dst, args, isolation, allow_overwrite=True)
            if rc != 0:
                rejected += 1
        return 1 if rejected else 0

    if out.exists() and not args.force:
        print(
            f"error: output exists (use --force to overwrite): {out}",
            file=sys.stderr,
        )
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    return _sanitize_one(inp, out, args, isolation, allow_overwrite=args.force)


def _sanitize_one(src: Path, dst: Path, args, isolation: str, allow_overwrite: bool) -> int:
    if dst.exists() and not allow_overwrite:
        print(f"error: output exists: {dst}", file=sys.stderr)
        return 2
    data = src.read_bytes()
    declared = src.suffix or None
    try:
        result = sanitize(
            data,
            output_format=args.format,
            isolation=isolation,
            declared_format=declared,
        )
    except RejectionError as e:
        print(
            f"{src.name}: Rejected {e.reason.value}: {e.detail}",
            file=sys.stderr,
        )
        return 1
    dst.write_bytes(result.data)
    if args.json:
        print(
            json.dumps(
                {"file": str(src), "output": str(dst), **result.report.to_dict()},
                indent=2,
            )
        )
    elif not args.quiet:
        print(
            f"{src.name} -> {dst} [{result.report.input_format} -> "
            f"{result.report.output_format}, {result.report.width}x{result.report.height}]"
        )
    return 0
