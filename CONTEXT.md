# Image Sanitizer

A Python library for the Ingest context: it takes an untrusted image and returns either a Clean image or a Rejection. Nothing else.

## Language

### Core contract

**Sanitize**:
To decode the pixels of an untrusted input and emit a brand-new file that inherits no structure from the input container.
_Avoid_: filter, strip, clean up, scan

**Clean**:
An output file whose every byte was produced by the library, not copied from the input. There is no third output state.
_Avoid_: safe file, verified image

**Rejection**:
The refusal to produce output for an input, delivered with a reason. The only alternative to a Clean result.
_Avoid_: error, warning, quarantine

**Rejection Reason**:
One of six stable, additive-only categories explaining a Rejection: UnsupportedFormat, Undecodable, LimitExceeded, MetadataInvalid, SandboxCrash, AuditFailed.

**Report**:
A description of the actions taken during one Sanitize call — what was Baked, dropped, re-attached. A Report states actions, never verdicts about the input.
_Avoid_: findings, detection, scan results

**Audit**:
The re-parse of a freshly encoded image asserting it contains only the structures the library wrote. An Audit failure is a Rejection.
_Avoid_: verify, scan

**Sandbox**:
The sacrificial process, apart from the caller's, in which untrusted decoding runs. A Sandbox that dies or hangs surfaces as a Rejection.

**Ingest**:
The calling context: server-side processing of untrusted uploads. The caller is a pipeline, not a human.

### Fidelity

**Visual Information**:
The contract on what must survive Sanitizing: bit-exact pixels *as displayed* (after orientation is Baked) for lossless-to-lossless rebuilds; visually lossless re-encoding when the input was lossy.

**Bake**:
To apply orientation to the pixel grid so the image is emitted upright; the orientation tag never survives Sanitizing.
_Avoid_: rotate, re-attach orientation

**Format Stability**:
A Clean image is emitted in the input's own format unless the caller overrides the output format per call.

**Metadata Whitelist**:
The vetted set of metadata fields re-attached to a Clean image. Unlisted metadata is dropped by default, not judged malicious.
_Avoid_: metadata preservation, EXIF copy

### Inputs

**Supported Format**:
An input format the library accepts and rebuilds: PNG, JPEG, GIF, WebP, BMP (v1).

**Rejected Format**:
An input format outside scope that receives a dedicated Rejection: SVG, HEIC/AVIF. TIFF is deferred, not silently mishandled.

**Bomb**:
An input whose decoded size is disproportionate to its encoded size, bounded by resource limits.
