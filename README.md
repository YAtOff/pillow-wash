# image-sanitizer

Sanitize untrusted images by **whitelist-rebuild**: decode the pixels, emit a
brand-new file that inherits **no structure** from the input, and re-attach
only vetted metadata.

Built for ingest pipelines processing untrusted uploads. Two outcomes exist
and only two: a **Clean** image, or a **Rejection** with a stable reason.
There is no pass-through state, no third branch, no "best effort".

```python
from image_sanitizer import sanitize

result = sanitize(untrusted_bytes)          # sandbox isolation by default
result.data                                 # Clean bytes
result.report.input_format                  # "JPEG"
result.report.actions                       # what was dropped / baked / kept
```

```console
$ image-sanitizer uploads/ -o clean/        # batch mode
$ image-sanitizer photo.jpg -o clean.jpg --json
```

## What it does

- **Rebuilds, never filters.** The input container is never copied: pixels
  are decoded, a fresh file is encoded from scratch. Polyglots, post-IEND
  trailers, smuggle chunks (`Raw profile type *`), EXIF thumbnails, XMP
  packets, MPO second images, and comment-segment webshells are gone *by
  construction* — not by signature detection. ([ADR-0001])
- **Metadata Whitelist (default-deny).** What survives: EXIF capture
  timestamps (306 / 36867, strictly validated) and the ICC color profile
  (lcms2-validated, size-capped). Orientation is **baked** into the pixels
  and the tag dropped. GPS and everything unlisted is dropped.
- **Audits its own output.** Every encoded file is re-parsed and must
  contain exactly the structures we wrote — Pillow's encoders auto-carry
  input-derived structures (JPEG `COM`, PNG `iCCP`/`tRNS`) unless suppressed
  and verified; an audit failure is a Rejection.
- **Decodes in a sandbox.** The default runs the decode in a sacrificial
  worker process with rlimits and a wall-clock timeout; a worker that dies
  or hangs is reported as a Rejection, not a crash of your service.
  ([ADR-0002]) (`isolation="none"` exists for tests/dev.)
- **Bomb limits.** Input size, dimensions, per-image and cumulative pixel
  budgets, and frame counts are enforced before/during decode — all
  caller-overridable with conservative defaults.
- **Reports actions, never verdicts.** The Report says what was dropped,
  baked, and re-attached, plus input/output SHA-256. It does not classify
  inputs as "malicious" — detection is explicitly out of scope.

## Formats

| In → Out (v1)       | Notes                                              |
| ------------------- | -------------------------------------------------- |
| PNG, JPEG, GIF, WebP, BMP | same format out unless `output_format=` is given |

SVG, HEIC/AVIF receive a dedicated `UnsupportedFormat` rejection (SVG is a
document format — a different sanitizer's job); TIFF is deferred.

## Fidelity contract (Visual Information)

- Lossless → lossless (PNG→PNG, GIF→GIF, lossless WebP): **bit-exact as
  displayed** — after orientation is baked into the pixel grid.
- Lossy inputs (JPEG, lossy WebP): re-encoded at high quality (JPEG q95,
  4:4:4 chroma), documented as visually lossless — a second lossy generation
  is unavoidable in a rebuild.
- Animated GIF/WebP: all frames and timing (durations, loop) preserved.

## What it does NOT do — read this

- **Steganography in pixel values is out of scope** ([ADR-0003]). A lossless
  rebuild preserves pixel data — including hidden data encoded in it —
  exactly. "Malicious content" here means *container-borne* threats.
- **It does not detect malware.** It removes attack surface. Do not use the
  Report as a verdict about intent.

## Rejections

`UnsupportedFormat` · `Undecodable` · `LimitExceeded` · `MetadataInvalid` ·
`SandboxCrash` · `AuditFailed` — closed set, additive-only across versions,
each a subclass of `RejectionError` carrying `reason` and `detail`.

## Limits (defaults)

| Limit              | Default        |
| ------------------ | -------------- |
| `max_input_bytes`  | 100 MB         |
| `max_still_pixels` | 50 MP          |
| `max_total_pixels` | 200 MP (anim.) |
| `max_frames`       | 1000           |
| `max_dimension`    | 16383          |
| `icc_max_bytes`    | 1 MiB          |
| `timeout_seconds`  | 30 s           |

```python
sanitize(data, limits=Limits(max_still_pixels=100_000_000))
```

## CLI

```console
$ image-sanitizer in.jpg -o out.jpg [--format png] [--json] [--quiet] [--force] [--in-process]
$ image-sanitizer uploads/ -o clean/
```

Exit codes: `0` all Clean · `1` at least one Rejection · `2` usage error.
Never mutates input files in place.

## Development

```console
$ uv venv && uv pip install --python .venv/bin/python -e '.[dev]'
$ .venv/bin/python -m pytest
```

The test suite is the security product: an adversarial corpus (crafted
polyglots, smuggle chunks, COM/iCCP carry-overs, bombs, malformed metadata,
encoder-betrayal fault injection, sandbox crash/timeout injection) plus
fidelity suites proving bit-exactness — see `tests/`.

**Real-world samples.** Genuinely malicious files are never committed.
Fill the gitignored `tests/corpus/` with
`.venv/bin/python scripts/fill_corpus.py all` — `generate` crafts hostile
inputs locally, `download` fetches SHA-256-pinned published samples
(ImageTragick PoCs, Pillow regression bombs, CVE-2023-4863 WebP) — or
point `IMAGE_SANITIZER_CORPUS` at a private directory. `tests/test_corpus.py`
runs each one under sandboxed isolation, asserting only the two-outcome
contract — Clean or Rejection — with per-file expectations pinnable in
`tests/corpus_manifest.json`. The module skips when no samples are
present, so CI stays green.

Design records: [`CONTEXT.md`](CONTEXT.md) (domain language),
[`docs/adr/`](docs/adr/) (the three hard-to-reverse decisions),
[`docs/research-image-sanitizer.md`](docs/research-image-sanitizer.md)
(threat-model evidence base).

[ADR-0001]: docs/adr/0001-whitelist-rebuild.md
[ADR-0002]: docs/adr/0002-decode-in-sandboxed-worker.md
[ADR-0003]: docs/adr/0003-steganography-out-of-scope.md
