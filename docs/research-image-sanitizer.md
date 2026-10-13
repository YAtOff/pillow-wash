# Image Sanitizer — Attack Vectors, Prior Art, and Metadata Policy (Research)

Research notes for designing a Python library that decodes untrusted images and re-emits a
clean, re-built copy preserving visual content and vetted metadata only. All claims are
cited to primary sources (official docs, specifications, source code, vendor/security
advisories) that were fetched and read directly.

---

## 1. Attack vectors carried in image files

### 1.1 Metadata as payload (EXIF / XMP / comments)

- **Embedded server-side code in metadata.** Web shells (PHP/JSP/ASP) can be hidden inside
  image metadata so the file passes naive "is it an image?" checks yet executes when a
  parser misstep or config error lets it run. PortSwigger's Web Security Academy notes that
  content validation via magic bytes "isn't foolproof. Using special tools, such as ExifTool,
  it can be trivial to create a polyglot JPEG file containing malicious code within its
  metadata" — and documents the full web-shell/upload taxonomy (extension tricks, Content-Type
  spoofing, `.htaccess`/`web.config` overrides, race conditions). The OWASP File Upload Cheat
  Sheet prescribes allowlisted extensions, server-generated filenames, storage outside the
  webroot, and for images: "decode and re-encode to an allowed image format, explicitly
  removing unnecessary metadata" — while warning that "rewriting does not guarantee that all
  malicious content is removed, and the image processor itself handles untrusted input."
  - https://portswigger.net/web-security/file-upload
  - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- **Metadata parsing is itself RCE surface.** CVE-2021-22204: "Improper neutralization of
  user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code
  execution when parsing the malicious image" (CVSS 7.8; in the CISA Known-Exploited
  Vulnerabilities catalog). Lesson: even *reading* metadata to decide what to keep requires
  a hardened, up-to-date parser.
  - https://ubuntu.com/security/CVE-2021-22204
- **Second-order injection.** Pillow's own security docs (Tampering threat T-1): "Pillow
  preserves EXIF, XMP, IPTC, ICC profiles, and comments when round-tripping images.
  Applications that store or render metadata without sanitisation are vulnerable to
  second-order injection (SQLi, XSS, command injection)." And T-2 (covert channel):
  "Pillow does not remove hidden data (JPEG comments, PNG text chunks) when re-saving."
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
- **XMP.** XMP (ISO 16684-1) is extensible RDF/XML with arbitrary custom namespaces and can
  even carry Base64-encoded binary (e.g., thumbnails) — an unbounded, XML-shaped payload
  container inside JPEG/TIFF/PNG/WebP. Any XMP-consuming XML parser must apply XXE hardening
  (reject DOCTYPEs, disable external entities/DTD loading), per the OWASP XXE cheat sheet.
  - https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

### 1.2 ICC profiles

An embedded ICC profile is a parsed binary structure (tags, lookup tables, `mft`/`A2B0`
matrices), not inert data. It is executed-ish input to color-management engines:

- **LittleCMS memory corruption from crafted profiles**: CVE-2013-4276, "Multiple
  stack-based buffer overflows in LittleCMS (aka lcms or liblcms) 1.19 and earlier allow
  remote attackers to cause a denial of service (crash) via a crafted ICC color profile."
  - https://ubuntu.com/security/CVE-2013-4276
- Pillow bundles littlecms2 (`_imagingcms`) and lists it among the C libraries processing
  attacker-controlled bytes (Elevation-of-privilege threat E-1).
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
- In JPEG the profile arrives in APP2 "ICC_PROFILE\0" markers split across up-to-64KB
  segments (reassembly logic is parser attack surface); in PNG it sits inside a
  zlib-compressed `iCCP` chunk.
  - https://github.com/python-pillow/Pillow/blob/main/src/PIL/JpegImagePlugin.py
  - https://github.com/python-pillow/Pillow/blob/main/src/PIL/PngImagePlugin.py

### 1.3 SVG: scripts, XXE, remote references

- **Stored XSS**: "if you can upload HTML files or SVG images, you can potentially use
  `<script>` tags to create stored XSS payloads" (same-origin caveat applies when served
  from the upload origin). PortSwigger Web Security Academy.
  - https://portswigger.net/web-security/file-upload
- **XXE**: SVG is XML; servers parsing XML-based uploads are a classic XXE vector
  (file disclosure/SSRF). General mitigation: reject DOCTYPE declarations, disable DTDs,
  external entities, and XInclude; treat partial hardening as failure.
  - https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- **Remote references / SSRF-ish leaks**: `<image href="http://…">`, `url()` in CSS, etc.
  The PHP `svg-sanitizer` library ships a `removeRemoteReferences(true)` option explicitly
  "to stop HTTP leaks," and notes its CSS handling is best-effort "defence-in-depth rather
  than a guarantee." ImageMagick's hardened policy separately disables SVG entity
  substitution.
  - https://github.com/darylldoyle/svg-sanitizer
  - https://imagemagick.org/security-policy/

### 1.4 Polyglot files and format confusion

- Polyglot construction is routine tooling, not exotic: PortSwigger's ExifTool-polyglot
  note above; the historical GIFAR class (GIF+JAR served to a JVM plugin) is the ancestor
  of today's image/code polyglots. The OWASP cheat sheet links ImageTragick
  (ImageMagick delegate abuse via crafted files) as the canonical parser-exploit example.
  - https://portswigger.net/web-security/file-upload
  - https://imagetragick.com/
- **Sniffing confusion**: Pillow's security page (Spoofing threat S-1): `Image.open()`
  "detects format by magic bytes, not file extension or MIME type. An attacker can name a
  file `safe.png` while its content is TIFF, JPEG 2000, or EPS, causing a different —
  potentially more dangerous — parser to run." Mitigation given: validate MIME and magic
  independently, and pass `Image.open(..., formats=[...])` with an allowlist.
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
- **Trailing data / trailers**: the PNG spec says a file ends at IEND, but ExifTool
  "will preserve any data found after this when writing unless it is specifically deleted
  with `-Trailer:All=`" — smuggled bytes after the image proper are a real, preserved-by-
  tools phenomenon that decode/re-encode eliminates.
  - https://exiftool.org/TagNames/PNG.html
- PNG text keys can smuggle entire other formats: unregistered `Raw profile type exif /
  icc / iptc / xmp / 8bim` zTXt/tEXt keys carry full EXIF/IPTC/ICC blobs inside "text"
  chunks (ImageMagick-era convention). Same source as above.

### 1.5 Decompression bombs and resource exhaustion

- **Pixel bombs**: Pillow threat D-1: "A small compressed image can expand to gigabytes in
  memory. `PIL.Image.MAX_IMAGE_PIXELS` raises `Image.DecompressionBombError` at 2× the
  limit and `Image.DecompressionBombWarning` at 1×." Guidance: never set it to `None`,
  treat the warning as an error, add OS/container memory limits.
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
- **Text-chunk bombs**: PNG zTXt/iTXt chunks are zlib-compressed and "can expand 1000x";
  Pillow caps them with `PngImagePlugin.MAX_TEXT_CHUNK` (per chunk, = SAFEBLOCK 64 KiB)
  and `MAX_TEXT_MEMORY` (64× that) — dedicated bomb defenses for metadata, not pixels.
  - https://github.com/python-pillow/Pillow/blob/main/src/PIL/PngImagePlugin.py
- **Structural bombs**: D-3: "Formats such as TIFF (nested IFD chains), animated GIF/WebP
  (many frames), and PNG (many text chunks) can exhaust CPU or memory before pixel data is
  decoded." D-2: even legal-size images can saturate CPU via resampling/filters.
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
- **Hard numeric limits** (Pillow "Limits" page): INT32 dimension ceiling, 2 GB single
  allocation cap (bounding 'RGB' images to ~0.5 Gpx), WebP library limit 16383×16383,
  ICO 256×256.
  - https://pillow.readthedocs.io/en/stable/reference/limits.html
- ImageMagick's security-policy page frames the same threat ("a crafted image, e.g.
  20000×20000") and answers with policy knobs: `width`/`height`/`area`/`time`/`memory`/
  `map`/`disk`/`list-length` (frame-count) limits.
  - https://imagemagick.org/security-policy/
- OWASP File Upload lists "ZIP bombs, XML bombs … or simply huge files" as availability
  attacks on upload pipelines.
  - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### 1.6 Parser memory-corruption CVEs in common decoders

- **CVE-2023-4863 (libwebp)** — the definitive modern case. "Heap buffer overflow in
  libwebp … and libwebp 1.3.2 allowed a remote attacker to perform an out of bounds memory
  write via a crafted HTML page. (Chromium security severity: Critical)" — CVSS 8.8,
  CISA KEV, exploit in the wild. Root cause per the isosceles analysis: OOB write in
  `BuildHuffmanTable` during VP8L (lossless) header parsing — corruption happens *before
  any pixel exists*, triggered by a deliberately invalid Huffman tree that pre-computed
  buffer sizes didn't account for.
  - https://ubuntu.com/security/CVE-2023-4863
  - https://blog.isosceles.com/the-webp-0day/
  - Fix commits: https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a
- **BLASTPASS (NSO/Pegasus, zero-click)**: Citizen Lab captured an iMessage zero-click
  deploying Pegasus; the chain smuggled the malicious image inside a PassKit attachment so
  it was processed outside the BlastDoor sandbox, then exploited an ImageIO buffer overflow
  (CVE-2023-41064, almost certainly the same libwebp bug). Consequences drawn by the
  analyst: image decoding is zero-click remote attack surface; there is "an over-reliance
  on fuzzing" (coverage-guided fuzzing had missed this bug for years); sensitive parsers
  "need to be adequately sandboxed."
  - https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/
  - https://blog.isosceles.com/the-webp-0day/
  - https://support.apple.com/en-us/HT213905
- **libpng**: CVE-2011-3026 — "Integer overflow in libpng … allows remote attackers to
  cause a denial of service or possibly have unspecified other impact … via … integer
  truncation."
  - https://ubuntu.com/security/CVE-2011-3026
- **JPEG 2000**: parsed by OpenJPEG in Pillow's plugin set; the Pillow security page names
  openjpeg among bundled C libraries with historical memory-corruption CVEs (E-1), and
  mat2 supports `jp2` only via external tooling. (JPEG 2000 bombs/exploits fall under the
  same decoder-hardening constraints.)
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
- **Non-decoder escalations inside an "image" library** (Pillow security page):
  E-2 EPS files invoke **Ghostscript via subprocess** (block EPS outright); E-3
  `ImageMath.unsafe_eval()` reaches Python `eval()`; E-4 user-controlled font paths reach
  FreeType. A sanitizer must constrain the *plugin surface*, not just the codecs.
  - https://pillow.readthedocs.io/en/stable/handbook/security.html

### 1.7 GIF and animated-format tricks

- Animated GIF/WebP/APNG multiply cost per file: many frames = many decode passes (Pillow
  D-3 lists "animated GIF/WebP (many frames)" as a parser-complexity DoS; ImageMagick's
  answer is the `list-length` sequence limit). APNG additionally has frame-control
  metadata (`fcTL` offsets/bboxes) that Pillow validates against the canvas ("APNG
  contains invalid frames") — animation metadata is another must-validate input class.
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
  - https://github.com/python-pillow/Pillow/blob/main/src/PIL/PngImagePlugin.py
  - https://imagemagick.org/security-policy/
- GIF also carries comment/application extensions (XMP lives in a GIF Application
  Extension per the XMP embedding table) — text-in-container is not a PNG-only concern.
  - https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
- Historical GIFAR-style image/Java-archive polyglots are the archetypal "two parsers, one
  file" attack; the modern general lesson (magic-byte sniffing, single-format allowlist)
  is covered in §1.4.

### 1.8 Thumbnail injection / embedded second images

- EXIF explicitly specifies an embedded **thumbnail in IFD1** — "a thumbnail for previewing
  the picture on the camera's LCD screen, in file managers, or in photo manipulation
  software." It is a second, complete JPEG inside your JPEG: it must be decoded/validated
  like any image, never copied through, and if you need a thumbnail you should regenerate
  one from pixels.
  - https://en.wikipedia.org/wiki/Exif
- XMP can carry Base64 thumbnails (binary-in-XML), and MPO files embed additional images
  (Pillow's MP parsing handles "Large Thumbnail" MP entries — `get_child_images()` exists
  on `ImageFile` for this class of problem).
  - https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
  - https://pillow.readthedocs.io/en/stable/reference/ImageFile.html
- PNG-side equivalents: `Raw profile type *` text keys and post-IEND trailers (§1.4).

---

## 2. How existing tools and platforms sanitize images

### 2.1 Pillow (the likely decode engine for a Python library)

Pillow's **Security handbook** (the "Pillow and image security" page) is the single most
useful primary source; it formalizes a STRIDE threat model for untrusted image input and a
prioritized mitigation list. Highlights directly applicable to a sanitizer library:

- Primary attack surface = parsing untrusted data; ~87 C files + bundled libjpeg/libpng/
  libtiff/libwebp/openjpeg/freetype/littlecms2 (E-1).
- Format allowlisting via `Image.open(..., formats=...)`; independent MIME/magic checks (S-1).
- Never `MAX_IMAGE_PIXELS = None`; treat `DecompressionBombWarning` as error (D-1).
- Strip metadata on output: "explicitly strip EXIF and XMP on save (set `exif=b""`,
  `icc_profile=None`, omit `pnginfo`); verify output with `exiftool` in CI" (I-1).
- Treat every value from `image.info` / `getexif()` / `image.text` as untrusted (T-1);
  clean round-trips require a fresh `image.copy()` and clearing `image.info` (T-2).
- Sandbox the process; keep C libs current; block EPS; log/alert on bomb warnings.
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
  - https://pillow.readthedocs.io/en/stable/reference/ImageFile.html
  - https://pillow.readthedocs.io/en/stable/reference/limits.html

**Does re-encoding via Pillow produce a file free of original container structure?**
Verified against the current plugin source code (read directly):

- The *container* is rebuilt from pixels — output is a freshly written stream of
  markers/chunks, so unknown/private chunks, trailing garbage, and embedded side data in
  the *input* cannot survive.
- **But re-encode ≠ metadata-free by default.** Per-format carry-overs differ:
  - JPEG (`JpegImagePlugin._save`): `exif = info.get("exif", b"")` → EXIF dropped unless
    passed; `icc_profile`/`xmp` written only if passed — **but**
    `comment = info.get("comment", im.info.get("comment"))` → the JPEG **COM comment is
    auto-carried from the input image** unless explicitly overridden.
  - PNG (`PngImagePlugin._save`): text chunks only via explicit `pnginfo`; `eXIf` only if
    passed — **but** `icc := im.encoderinfo.get("icc_profile", im.info.get("icc_profile"))`
    → the **iCCP profile is auto-carried**, and `transparency` is auto-carried too.
  - Sources: https://github.com/python-pillow/Pillow/blob/main/src/PIL/JpegImagePlugin.py
    and https://github.com/python-pillow/Pillow/blob/main/src/PIL/PngImagePlugin.py
- Practical consequence (matches the T-2 warning): a sanitizer built on Pillow must
  suppress per-format carry-overs explicitly and then *verify* output chunk-by-chunk, not
  assume "re-encoded therefore clean."

### 2.2 sharp / libvips (Node) — the CDN-ecosystem reference

- "By default **all metadata will be removed**, which includes EXIF-based orientation.
  See `withMetadata` for control over this." Opt-ins are granular: `keepExif`,
  `keepIccProfile`, `keepXmp`, `keepMetadata`, `withExif`/`withIccProfile`/`withXmp`
  (write-new). Note also: "If no explicit format is set, the output format will match the
  input image, **except SVG input which becomes PNG output**" — i.e., the default SVG
  policy is *rasterize*, which is itself a sanitization decision.
  - https://sharp.pixelplumbing.com/api-output

### 2.3 ImageMagick — policy-based defense in depth

- Ships selectable policies (`open` / `limited` / `secure` / `websafe`); the websafe
  policy "deactivates the capability to read from or write to any image formats other than
  web-safe formats like GIF, JPEG, and PNG" and "prohibits the execution of image filters
  and indirect reads." Hardened policy example: resource limits (memory 256 MiB, area
  32 MP, width/height 4 KP, time 60 s, list-length 16 frames), all delegates and filters
  disabled, path restrictions (`@file`, pipes, `../*`), symlinks off, and SVG entity
  substitution disabled. OWASP's file-upload guidance links ImageMagick's `-strip` option
  and this policy page as the reference practice.
  - https://imagemagick.org/security-policy/
  - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html

### 2.4 Dedicated open-source sanitizers

- **mat2** (Python, library + CLI, used by Tails-adjacent tooling and the "Metadata
  Cleaner" GNOME app): "getting rid, as much as possible, of metadata" across png/jpeg/
  gif/bmp/tiff/svg(svgz)/webp/avif/jxl and many non-image formats, using gdk-pixbuf,
  librsvg, FFmpeg, and ExifTool underneath. Notable design choices worth copying: an
  `--unknown-members policy` switch (abort/omit/keep) for unknown structures inside
  archive-style files; a `-L/--lightweight` mode trading removal strength for data
  fidelity; and the honest caveat — "There is no reliable way to detect every single
  possible metadata for complex file formats … you shouldn't rely on metadata's presence
  to decide if your file must be cleaned or not."
  - https://github.com/jvoisin/mat2
- **svg-sanitizer** (PHP, `enshrined/svg-sanitize`): whitelist-based SVG/XML sanitizer
  "largely borrowed from DOMPurify"; configurable tag/attribute allowlists;
  `removeRemoteReferences(true)` to stop HTTP leaks (with documented best-effort CSS
  caveats). Deployed in WordPress (safe-svg plugin), TYPO3 core ≥ 9.5, and a Drupal
  module — i.e., this is the battle-tested pattern for *keeping* SVG as SVG.
  - https://github.com/darylldoyle/svg-sanitizer
- **DOMPurify** (JS): DOM-only XSS sanitizer for HTML/MathML/**SVG** with allow/block
  lists, URI regexp controls, `SAFE_FOR_XML`, hooks, and a public catalog of attack
  classes/bypass history; it inspired the standardized HTML Sanitizer API (now in the
  WHATWG HTML spec). Relevant precedent: sanitizing a graph-structured format is a
  whitelist problem with a documented bypass arms race.
  - https://github.com/cure53/DOMPurify
- ExifTool itself is the standard *verification* tool (Pillow's docs recommend exactly
  that in CI), and its PNG tag tables document the tricky corners (post-IEND trailers,
  `Raw profile type *` smuggling keys, sRGB-vs-iCCP exclusivity).
  - https://exiftool.org/TagNames/PNG.html

### 2.5 Cloud / platform behavior

- **Cloudflare Polish**: "Polish **strips metadata** from images and reduces image size
  through lossy or lossless compression to accelerate the speed of image downloads" —
  an explicit, documented strip-on-serve product behavior. Cloudflare Images
  transformations similarly produce newly-processed derivative images at new URLs
  ("Images created this way are already optimized").
  - https://developers.cloudflare.com/images/polish/
- **AWS**: no authoritative AWS-published statement on EXIF stripping was verifiable in
  this research pass (the common building block, sharp, is strip-by-default per §2.2 —
  but AWS's own docs were not fetched; treat as open item).
- **Browsers / OS vendors**: browsers do not re-encode images when re-serving them (the
  HTTP cache is byte-faithful); the interesting platform precedent is Apple's **BlastDoor**
  — a dedicated sandbox through which iMessage content (including images) is decoded —
  which the BLASTPASS chain had to *route around* (via PassKit) to succeed. That is the
  strongest available endorsement of "decode untrusted images only inside a hardened,
  isolated process." Post-CVE-2023-4863, Apple/Google/Android all shipped libwebp fixes;
  the analyst's conclusion: sensitive parser surfaces need sandboxing plus code review,
  not fuzzing alone.
  - https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/
  - https://blog.isosceles.com/the-webp-0day/
  (A Mozilla/Firefox-specific "screenshot re-encode" citation could not be verified in
  this pass; Firefox screenshots are canvas-rendered PNGs, but that is code behavior, not
  a documented sanitization policy — flagged as open item rather than asserted.)

---

## 3. Metadata schemas worth whitelisting

### EXIF (JEITA/CIPA, TIFF-IFD based)

- **Orientation (tag 274)** — the one tag with direct visual-fidelity impact. If you strip
  it, you must first bake rotation into the pixels, or every rotated phone photo displays
  sideways. sharp documents this exact coupling: default strip "includes EXIF-based
  orientation," i.e., strip-by-default presumes auto-rotation at load. A sanitizer should
  apply orientation to pixels, then drop the tag (or explicitly re-emit orientation = 1).
  - https://sharp.pixelplumbing.com/api-output
  - https://en.wikipedia.org/wiki/Exif
- **GPS IFD** — privacy liability by default. Pillow lists "GPS coordinates, author names,
  software version strings, and ICC profiles" as inadvertent-disclosure risks in publicly
  served output (I-1); Wikipedia's Exif article carries dedicated Geolocation and
  "Privacy and security" sections. GPS is a *requirement* only for products whose feature
  is "where was this taken" (maps, photo organizers). Default: strip; opt-in preserve with
  an explicit user-facing choice. Note sharp's `withExif` example shows GPS lives in
  IFD3 as rational triples — preserve-then-rewrite must reconstruct, not copy, the IFD.
  - https://pillow.readthedocs.io/en/stable/handbook/security.html
  - https://en.wikipedia.org/wiki/Exif
  - https://sharp.pixelplumbing.com/api-output
- **Everything else in EXIF** (Make/Model, timestamps, exposure, MakerNotes): MakerNotes
  are vendor-specific binary blobs (opaque parser surface); camera/timestamp data is
  fingerprinting material. Whitelist at most: Orientation (baked), and optionally
  Copyright/Artist/DateTimeOriginal as *rewritten typed values*, never raw IFD copy — the
  IFD also contains IFD1 (thumbnail, §1.8).

### ICC color profile

- Preserve-or-normalize is a genuine product decision: dropping ICC shifts colors for
  wide-gamut (Adobe RGB/P3) images; keeping it means re-embedding a parsed binary blob
  (§1.2 attack surface; Pillow auto-carries it on PNG re-save — §2.1). Sanitizer policy:
  either (a) transform to sRGB and emit an `sRGB` chunk / no profile, or (b) pass the
  profile through only after size cap + parse validation with an up-to-date lcms2, or
  (c) replace with a known-good pinned profile. Also respect container rules: "You must
  either have sRGB or iCCP" (PNG; sRGB chunk must be dropped when iCCP is written).
  - https://github.com/python-pillow/Pillow/blob/main/src/PIL/PngImagePlugin.py
  - https://exiftool.org/TagNames/PNG.html
  - https://ubuntu.com/security/CVE-2013-4276

### XMP (ISO 16684-1)

- Extensible RDF/XML with custom namespaces and Base64 binary capability (§1.1). Partial
  preservation is only meaningful as *re-serialization of a few whitelisted namespaces*
  (dc:rights, dc:creator, xmp:License…) into a freshly built packet — never passthrough,
  because the packet can contain arbitrary XML. Default: strip (Pillow T-1/I-1; sharp's
  keepXmp is an explicit opt-in).
  - https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
  - https://sharp.pixelplumbing.com/api-output
  - https://pillow.readthedocs.io/en/stable/handbook/security.html

### PNG text chunks (tEXt / zTXt / iTXt)

- Spec keyword set (per ExifTool's PNG TextualData table): Title, Author, Description,
  Copyright, Creation Time (`Creation Time`), Software, Source, Disclaimer, Comment,
  Warning, plus XML:com.adobe.xmp as the XMP iTXt location. "The PNG TextualData format
  allows arbitrary tag names" — and unregistered keys like `Raw profile type exif/icc/
  iptc/xmp/8bim` smuggle whole foreign payloads. Whitelist exact keyword strings, cap
  value lengths, and write only freshly encoded tEXt/iTXt (zlib budget applies, §1.5).
  - https://exiftool.org/TagNames/PNG.html

### Structural/color chunks (PNG)

- Rendering-critical, cheap, and safe to regenerate: `pHYs` (density), `gAMA`/`cHRM`/
  `sRGB`/`cICP` (color), `tRNS` (transparency — Pillow auto-carries it, and it affects
  display), `PLTE` (palette). Decide: keep structural chunks derived from the decoded
  image, never copied verbatim from input. Sources as above (PngImagePlugin, exiftool).

---

## 4. Design implications — hard constraints for any image sanitizer

1. **Decode → pixels → re-encode. Never pass container bytes through.** The output file
   must be written chunk-by-chunk by the sanitizer's encoder. This kills trailers,
   unknown/private chunks, `Raw profile type *` smuggling, and container-level polyglots
   by construction. (OWASP file-upload guidance; ExifTool PNG trailer note; PortSwigger.)
2. **Re-encode ≠ clean: audit per-format carry-overs and verify output.** Pillow re-encode
   silently keeps JPEG COM comments and PNG iCCP/tRNS unless suppressed (verified in
   source). Assert on the *output*: parse it and fail if anything outside the expected
   chunk/metadata set appears — run `exiftool` assertions in CI, exactly as Pillow's own
   security page recommends.
3. **Enforce resource limits before and during decode.** Pixel budget (`MAX_IMAGE_PIXELS`
   on, never `None`; bomb-warning treated as error), explicit width/height caps below the
   library maxima, input file-size cap, wall-clock timeout, memory cap, animation
   frame-count cap (ImageMagick `list-length` analog), PNG text-chunk size/memory caps.
   (Pillow D-1/D-2/D-3 + Limits; ImageMagick policy.)
4. **Sandbox the decoding process.** CVE-2023-4863/BLASTPASS prove heap corruption happens
   pre-pixels in ubiquitous C decoders, that fuzzing misses bugs for years, and that
   Apple's answer (BlastDoor) was a sandbox the attackers had to route around. Run decode
   in a restricted subprocess/container with memory/time limits; keep libjpeg/libpng/
   libtiff/libwebp/openjpeg/littlecms2 pinned and current.
5. **Allowlist formats; block code-executing ones.** `Image.open(..., formats=[...])`,
   independent magic-byte + MIME checks (they can disagree by design — S-1). Reject EPS
   unconditionally (Ghostscript subprocess), and treat SVG as *code*: rasterize by default
   (sharp's precedent: SVG→PNG), or run a DOMPurify/svg-sanitizer-style whitelist pass
   with DOCTYPEs/external entities off and remote references removed — never regexes.
6. **Default-deny metadata; rebuild, don't copy.** Strip EXIF/XMP/IPTC/comments/pnginfo;
   whitelist back only: orientation (baked into pixels), a normalized color story
   (sRGB-ify or validated/pinned ICC), and a short list of typed, length-capped text
   fields re-encoded from scratch. GPS off by default (privacy), on only as an explicit
   product opt-in. Treat every metadata value as an untrusted string (Pillow T-1/I-1).
7. **Never re-embed second images.** Drop EXIF IFD1 thumbnails, XMP Base64 thumbnails,
  MPO child images, and embedded profiles-in-text; regenerate any thumbnail you need from
   the sanitized pixels (recursively sanitized).
8. **Constrain the library surface, not just codecs.** No EPS/Ghostscript, no
   `ImageMath.unsafe_eval` on user input, no user-influenced font paths, no shell-outs
   on filenames; generate storage names server-side, store outside webroot, serve a
   correct Content-Type with `X-Content-Type-Options: nosniff` (Pillow E-2/E-3/E-4; OWASP;
   PortSwigger).
9. **Fail closed and log.** Unknown structures → reject (mat2's `abort` default for
   unknown members). Log hash/format/dimensions; alert on `DecompressionBombWarning`/
   `Error` and `UnidentifiedImageError` (Pillow R-1).
10. **Honor the visual-fidelity contract.** Rotation must be applied before the
    orientation tag is dropped; transparency and gamma/primaries handled or colors and
    alpha shift; accept that lossy→lossy re-encode costs a generation of quality and make
    the output format/quality an explicit policy. mat2's `--lightweight` mode is prior art
    for offering a fidelity/max-removal dial.
11. **Don't trust detection as the gate.** "There is no reliable way to detect every
    possible metadata" (mat2) and signature checks are "pretty common and easy" to bypass
    (OWASP) — sanitize unconditionally, then verify the artifact, rather than deciding
    per-file whether cleaning is needed.

---

### Source index (primary URLs)

- Pillow Security handbook — https://pillow.readthedocs.io/en/stable/handbook/security.html
- Pillow Limits — https://pillow.readthedocs.io/en/stable/reference/limits.html
- Pillow ImageFile — https://pillow.readthedocs.io/en/stable/reference/ImageFile.html
- Pillow JpegImagePlugin source — https://github.com/python-pillow/Pillow/blob/main/src/PIL/JpegImagePlugin.py
- Pillow PngImagePlugin source — https://github.com/python-pillow/Pillow/blob/main/src/PIL/PngImagePlugin.py
- OWASP File Upload Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP XXE Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy, File uploads — https://portswigger.net/web-security/file-upload
- ImageMagick security policy — https://imagemagick.org/security-policy/
- sharp output options — https://sharp.pixelplumbing.com/api-output
- Cloudflare Polish — https://developers.cloudflare.com/images/polish/
- mat2 — https://github.com/jvoisin/mat2
- svg-sanitizer — https://github.com/darylldoyle/svg-sanitizer
- DOMPurify — https://github.com/cure53/DOMPurify
- ExifTool PNG tag names — https://exiftool.org/TagNames/PNG.html
- Wikipedia: Exif — https://en.wikipedia.org/wiki/Exif
- Wikipedia: XMP — https://en.wikipedia.org/wiki/Extensible_Metadata_Platform
- CVE-2023-4863 (libwebp) — https://ubuntu.com/security/CVE-2023-4863
- WebP 0-day analysis (isosceles) — https://blog.isosceles.com/the-webp-0day/
- Citizen Lab, BLASTPASS — https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/
- Apple HT213905 — https://support.apple.com/en-us/HT213905
- libwebp fix commit — https://github.com/webmproject/libwebp/commit/902bc9190331343b2017211debcec8d2ab87e17a
- CVE-2021-22204 (ExifTool DjVu RCE) — https://ubuntu.com/security/CVE-2021-22204
- CVE-2011-3026 (libpng integer overflow) — https://ubuntu.com/security/CVE-2011-3026
- CVE-2013-4276 (LittleCMS ICC overflows) — https://ubuntu.com/security/CVE-2013-4276
- ImageTragick — https://imagetragick.com/
