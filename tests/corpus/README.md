# Real-world corpus (provided out-of-band — NEVER committed)

Drop real malicious/hostile image samples here. Everything in this
directory except this README is gitignored; the repository never stores,
and never distributes, live malware.

## Quick start: the fill script

```console
$ .venv/bin/python scripts/fill_corpus.py all
```

- `generate` — crafts hostile samples into `crafted/` (webshell trailers,
  EICAR payload, smuggle chunks, XMP, MPO concat, GIF comment webshell,
  wrong extensions, dimension/pixel bombs, truncation).
- `download` — fetches genuinely malicious published samples into
  `downloaded/`, every one pinned by SHA-256 (a mismatch aborts):
  ImageTragick PoCs, Pillow regression bombs/crashers, and the
  CVE-2023-4863 WebP PoCs. A `SOURCES.md` provenance file is written
  alongside them.
- Both update `tests/corpus_manifest.json` with per-file expectations
  and then verify each sample against the sandboxed sanitizer — a
  mismatch exits non-zero. `--force` overwrites, `--only SUBSTR`
  filters, `--skip-verify` skips the check pass.

## Manual use

1. Copy sample files into this directory (subdirectories are fine; they
   are scanned recursively). Extensions don't matter — the sanitizer
   sniffs magic bytes, so `polyglot.bin` works as well as `poc.gif`.
2. Optionally pin the expected outcome per file in
   [`tests/corpus_manifest.json`](../corpus_manifest.json):

   ```json
   {
     "files": {
       "imagetragick-poc.gif": "Undecodable",
       "webp-cve-2023-4863.webp": "SandboxCrash",
       "holiday-photo.jpg": "clean",
       "unknown-weirdness.png": "any"
     }
   }
   ```

   Keys are paths relative to this directory. Unlisted files default to
   `"any"` — Clean **or** any Rejection, never a crash, never a hang.
3. Run the suite:

   ```console
   $ .venv/bin/python -m pytest tests/test_corpus.py -v
   $ .venv/bin/python -m pytest -m "not corpus"   # everything else
   ```

   With no samples present the module simply skips, so CI stays green.

## Alternative location

Point `IMAGE_SANITIZER_CORPUS` at any directory (or a single file) —
e.g. a private samples checkout you keep outside this repo:

```console
$ IMAGE_SANITIZER_CORPUS=~/samples/malicious-images .venv/bin/python -m pytest -m corpus
```

## Ground rules

- Samples are only ever **read as bytes** and decoded inside the
  sanitizer's sandboxed worker (rlimits + wall-clock timeout). Never
  open, render, or execute them yourself.
- Manifest expectations are committed; sample bytes are not. If a sample
  is legally sensitive, keep it in the out-of-band location only.
- Good sources: ImageTragick PoCs, decoder CVE PoCs (libpng, libjpeg-turbo,
  giflib, libwebp — e.g. CVE-2023-4863), polyglot databases, classic
  decompression bombs, CTF stego/polyglot challenges.
