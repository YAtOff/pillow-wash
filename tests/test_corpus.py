"""Real-world corpus: malicious samples provided out-of-band, never committed.

Samples live in ``tests/corpus/`` (gitignored) or wherever
``IMAGE_SANITIZER_CORPUS`` points — a private samples repo on your disk is
fine. The module auto-discovers them and skips entirely when none are
present, so CI without the corpus stays green.

Contract under test: for any real-world input the sanitizer ends **Clean**
or with a **RejectionError** — never a crash, never a hang — under the
*default sandboxed isolation* (unlike the synthetic tests, which use
``isolation="none"``, because surviving a hostile decode is exactly what
ADR-0002 built the sandbox for).

Per-file expectations live in the committed ``tests/corpus_manifest.json``:

    "<path relative to corpus root>":
        "clean"                  must sanitize successfully
        "any"                    Clean or any Rejection (the default)
        "<RejectionReason name>" must reject with exactly that reason,
                                 e.g. "Undecodable", "LimitExceeded", ...
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import image_sanitizer
from image_sanitizer import RejectionError, RejectionReason, sanitize

_HERE = Path(__file__).resolve().parent
_MANIFEST = _HERE / "corpus_manifest.json"

_SKIP_MSG = (
    "no real-world corpus present — drop samples into tests/corpus/ or set "
    "IMAGE_SANITIZER_CORPUS (see tests/corpus/README.md)"
)

# The six stable rejection class names, resolved from the public package so
# the mapping stays in sync as reasons are added (additive-only).
_REJECTION_CLASSES: dict[str, type[Exception]] = {
    reason.value: getattr(image_sanitizer, reason.value) for reason in RejectionReason
}

_VALID_EXPECTATIONS = {"clean", "any", *_REJECTION_CLASSES}


def _corpus_files() -> list[Path]:
    """All sample files under the corpus root (env var override wins)."""
    env = os.environ.get("IMAGE_SANITIZER_CORPUS")
    root = Path(env).expanduser() if env else _HERE / "corpus"
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() not in {".md", ".json", ".txt"}
        and not p.name.startswith(".")
    )


_FILES = _corpus_files()

if not _FILES:
    pytest.skip(_SKIP_MSG, allow_module_level=True)


def _corpus_key(path: Path) -> str:
    """Manifest key: path relative to the corpus root, POSIX-style."""
    env = os.environ.get("IMAGE_SANITIZER_CORPUS")
    root = Path(env).expanduser() if env else _HERE / "corpus"
    if root.is_file():
        return path.name
    return path.relative_to(root).as_posix()


def _load_manifest() -> dict[str, str]:
    if not _MANIFEST.is_file():
        return {}
    raw = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    files = raw.get("files", {})
    assert isinstance(files, dict), "corpus_manifest.json: 'files' must be an object"
    return files


_MANIFEST_FILES = _load_manifest()

pytestmark = pytest.mark.corpus


@pytest.mark.parametrize("path", _FILES, ids=_corpus_key)
def test_real_world_sample(path: Path) -> None:
    key = _corpus_key(path)
    expectation = _MANIFEST_FILES.get(key, "any")
    assert expectation in _VALID_EXPECTATIONS, (
        f"corpus_manifest.json: unknown expectation {expectation!r} for {key!r} "
        f"(valid: {sorted(_VALID_EXPECTATIONS)})"
    )

    data = path.read_bytes()

    if expectation == "clean":
        result = sanitize(data)  # sandboxed isolation by default
        assert result.data, "Clean result must carry bytes"
        assert result.report.input_sha256, "Clean result must carry a report"
        return

    try:
        sanitize(data)
        rejection: RejectionError | None = None
    except RejectionError as rej:
        rejection = rej

    if expectation == "any":
        return  # Clean or any Rejection are both acceptable

    assert rejection is not None, f"{key}: expected {expectation}, got Clean"
    expected_cls = _REJECTION_CLASSES[expectation]
    assert isinstance(rejection, expected_cls), (
        f"{key}: expected {expectation}, got "
        f"{type(rejection).__name__} ({rejection.detail})"
    )
