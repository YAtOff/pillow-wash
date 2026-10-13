# Steganography in pixel values is out of scope

**Status**: accepted

"Removes any malicious content" cannot be honored for payloads encoded in pixel values: a
lossless rebuild preserves LSB steganography *exactly* (bit-exact pixels is the Visual
Information contract), and even lossy re-encoding is no guarantee against robust steg.

We decided "malicious content" means container-borne threats only — structures, metadata,
polyglots, trailers, second images. Pixel-value steganography is a documented non-goal, stated
prominently rather than quietly assumed.

## Consequences

- The README must say what the library does *not* do as loudly as what it does.
- Attempting steg removal later would break Visual Information (it forces lossy re-encoding of
  everything) — reversing this means reversing the fidelity contract, not just adding a feature.
