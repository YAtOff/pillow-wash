"""Slice 14: the CLI — explicit outputs, batch mode, exit codes, --json.

Seam: `pillow_wash.cli.main(argv)` (the console-script entry point).
Never mutates in place; exits 0 clean / 1 rejections / 2 usage error.
"""

from __future__ import annotations

import json

import pytest

from pillow_wash.cli import main

from imgfactory import make_jpeg, make_png


def test_single_file(tmp_path) -> None:
    src = tmp_path / "in.png"
    src.write_bytes(make_png())
    dst = tmp_path / "out.png"

    rc = main([str(src), "-o", str(dst)])

    assert rc == 0
    assert dst.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_single_file_with_json_report(tmp_path, capsys) -> None:
    src = tmp_path / "in.png"
    src.write_bytes(make_png())
    dst = tmp_path / "out.png"

    rc = main([str(src), "-o", str(dst), "--json"])

    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["input_format"] == "PNG"
    assert len(report["input_sha256"]) == 64


def test_overwrite_refused_without_force(tmp_path) -> None:
    src = tmp_path / "in.png"
    src.write_bytes(make_png())
    dst = tmp_path / "out.png"
    dst.write_bytes(b"precious existing data")

    rc = main([str(src), "-o", str(dst)])

    assert rc == 2
    assert dst.read_bytes() == b"precious existing data"


def test_overwrite_allowed_with_force(tmp_path) -> None:
    src = tmp_path / "in.png"
    src.write_bytes(make_png())
    dst = tmp_path / "out.png"
    dst.write_bytes(b"old")

    rc = main([str(src), "-o", str(dst), "--force"])

    assert rc == 0
    assert dst.read_bytes()[:4] == b"\x89PNG"


def test_batch_mode_cleans_and_reports_rejections(tmp_path, capsys) -> None:
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "a.png").write_bytes(make_png())
    (indir / "b.jpg").write_bytes(make_jpeg())
    (indir / "evil.svg").write_bytes(
        b"<svg xmlns='http://www.w3.org/2000/svg'><script>x</script></svg>"
    )
    outdir = tmp_path / "out"

    rc = main([str(indir), "-o", str(outdir)])

    assert rc == 1  # one rejection occurred
    assert (outdir / "a.png").read_bytes()[:4] == b"\x89PNG"
    assert (outdir / "b.jpg").read_bytes()[:2] == b"\xff\xd8"
    assert not (outdir / "evil.svg").exists()
    err = capsys.readouterr().err
    assert "UnsupportedFormat" in err
    assert "evil.svg" in err


def test_missing_input_is_usage_error(tmp_path) -> None:
    rc = main([str(tmp_path / "nope.png"), "-o", str(tmp_path / "x.png")])
    assert rc == 2
