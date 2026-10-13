# Decode untrusted images in a Sandbox worker by default

**Status**: accepted

Memory-corruption CVEs in bundled C decoders (libwebp CVE-2023-4863, exploited in the wild via
BLASTPASS; libpng CVE-2011-3026) fire *before* pixels exist, and fuzzing did not catch them.
An in-process decode would make the sanitizer itself the breach vector into the calling Ingest
service — the one component guaranteed to touch hostile bytes should not hold service
credentials. Apple's answer to the same class was a dedicated decode sandbox (BlastDoor).

We decided the decode step runs in a library-managed worker process — bytes in, bytes out,
rlimits plus wall-clock timeout — by default. An in-process mode exists only as an explicit
opt-in (`isolation="none"`) for tests and development.

## Consequences

- Process-spawn overhead per image (poolable); decode is CPU-bound so asyncio callers lose little.
- A Sandbox that crashes, is OOM-killed, or times out is indistinguishable from hostile input:
  both surface as a Rejection. Fail-closed applies to our own machinery.
