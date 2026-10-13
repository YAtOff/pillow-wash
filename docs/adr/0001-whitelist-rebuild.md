# Sanitize by whitelist-rebuild, not by filtering

**Status**: accepted

Untrusted images carry their realistic attack surface in container structures — EXIF/XMP/ICC
payloads, polyglots, trailers, unknown chunks, second images. We decided the library *Sanitizes*
by decoding pixels and emitting a brand-new file whose only non-pixel content comes from the
Metadata Whitelist, never by parsing the original container and deleting known-bad parts.

Filtering was rejected because it requires trusting a parser against attacker-controlled input
(parser CVEs become the library's CVEs) and devolves into signature-chasing that is "pretty
common and easy" to bypass (OWASP File Upload Cheat Sheet); mat2 independently concluded
detection cannot be complete, so cleaning must not be gated on it.

## Consequences

- Unlisted metadata is dropped by default — a documented contract, not data loss by accident.
- Re-encoding does NOT make output clean by itself: encoders auto-carry metadata (Pillow JPEG
  save carries the COM comment; PNG save carries iCCP/tRNS — verified in plugin source). The
  output must be re-parsed and audited against the expected structure set.
- The fidelity contract must be explicit (re-encode of lossy input is a second lossy generation).
- Steganography in pixel values is untouched by this architecture (separate scope decision).
