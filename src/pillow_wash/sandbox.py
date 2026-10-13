"""Sandbox isolation: the sacrificial worker process for untrusted decodes.

Per ADR-0002: memory-corruption decoder CVEs fire *before* pixels exist, so
the default decode path runs in a separate process with rlimits and a
wall-clock timeout. A worker that dies, hangs, or is OOM-killed is
indistinguishable from hostile input: both surface as a SandboxCrash
Rejection.

Test hook: the environment variable ``PILLOW_WASH_FAULT`` (values
``exit`` / ``hang``) makes the worker misbehave on purpose; it exists so the
crash/timeout mappings are observable through the public seam.
"""

from __future__ import annotations

import multiprocessing
import os
import resource
import time

from .exceptions import (
    AuditFailed,
    LimitExceeded,
    MetadataInvalid,
    RejectionError,
    RejectionReason,
    SandboxCrash,
    Undecodable,
    UnsupportedFormat,
)
from .report import SanitizedImage

__all__ = ["run_sandboxed"]

_FAULT_ENV = "PILLOW_WASH_FAULT"

_SUBCLASSES = {
    RejectionReason.UNSUPPORTED_FORMAT: UnsupportedFormat,
    RejectionReason.UNDECODABLE: Undecodable,
    RejectionReason.LIMIT_EXCEEDED: LimitExceeded,
    RejectionReason.METADATA_INVALID: MetadataInvalid,
    RejectionReason.SANDBOX_CRASH: SandboxCrash,
    RejectionReason.AUDIT_FAILED: AuditFailed,
}


def run_sandboxed(data: bytes, options: dict) -> SanitizedImage:
    limits = options.get("limits")
    timeout = getattr(limits, "timeout_seconds", 30.0)

    ctx = multiprocessing.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    payload = (child_conn, data, options)
    proc = ctx.Process(target=_worker_main, args=payload, daemon=True)
    proc.start()
    child_conn.close()  # parent keeps only its end
    try:
        proc.join(timeout)
        if proc.is_alive():
            proc.terminate()
            proc.join(5)
            raise SandboxCrash(
                f"sandbox exceeded {timeout}s wall clock and was terminated"
            )
        if not parent_conn.poll():
            raise SandboxCrash("sandbox produced no result")
        kind, a, b = parent_conn.recv()
        if kind == "ok":
            return SanitizedImage(a, b)
        if kind == "rejection":
            reason = RejectionReason(a)
            raise _SUBCLASSES[reason](b)
        # kind == "crash"
        raise SandboxCrash(f"sandbox pipeline raised unexpectedly: {a}")
    except SandboxCrash:
        raise
    except RejectionError:
        raise
    except (OSError, ValueError, EOFError) as e:
        raise SandboxCrash(f"sandbox communication failed: {e}") from e
    finally:
        parent_conn.close()
        if proc.is_alive():
            proc.terminate()
            proc.join(5)


def _worker_main(conn, data: bytes, options: dict) -> None:
    try:
        fault = os.environ.get(_FAULT_ENV)
        if fault == "exit":
            os._exit(1)
        if fault == "hang":
            time.sleep(3600)
        _apply_rlimits(options.get("limits"))
        from .pipeline import sanitize_bytes

        out, report = sanitize_bytes(
            data,
            options.get("limits"),
            options.get("output_format"),
            options.get("declared_format"),
        )
        conn.send(("ok", out, report))
    except RejectionError as e:
        conn.send(("rejection", e.reason.value, e.detail))
    except BaseException as e:  # fail-closed on anything unexpected
        try:
            conn.send(("crash", f"{type(e).__name__}: {e}"))
        except Exception:
            pass
    finally:
        conn.close()


def _apply_rlimits(limits) -> None:
    """Best-effort rlimits inside the worker (POSIX only, never fatal)."""
    try:
        timeout = int(getattr(limits, "timeout_seconds", 30.0))
        cpu = max(timeout, 1)
        mem = 3 * 1024 * 1024 * 1024  # 3 GiB decode budget
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    except (OSError, ValueError, ImportError):
        pass
