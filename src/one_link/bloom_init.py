"""Bloom-init transfer handshake — Phase B.

Per ``FILE_ENGINE_V2_PLAN.md``:

    Bloom-filter transfer init — receiver sends Bloom of chunk hashes;
    sender XORs against manifest; sends only true delta. Unifies fresh
    / resume / dedup. Reduces bytes-on-wire by 75-93% in the
    common-case resume regime.

This module is the daemon-facing surface for that handshake. It wraps
``one_link_native.bloom`` with:

- A simple API to build a receiver-side Bloom from a chunk-id list.
- A symmetric sender-side filter that removes chunks the receiver
  already has from a manifest.
- Encoded wire-frame helpers (size-prefixed bytes for transport).

When ``one_link_native.bloom`` is not installed the module's
``HAS_NATIVE`` flag is False and callers fall back to the legacy
manifest-then-chunks path. The capability advertised on the wire
(``BLOOM_INIT_V1``) gates the entire handshake, so this is a pure
feature-flag with no protocol break.

Sizing:
- For ``n`` chunks the receiver-side Bloom is sized at ``n`` elements
  with a target false-positive rate of 5%. This is the sweet spot
  between filter size and savings — see
  ``scripts/bloom_init_savings_measure.py``.
- The 5% FP rate means ~5% of chunks the receiver actually has will
  appear "missing" to the sender and get re-transferred. That's the
  honest trade-off: 5% over-transfer vs ~80% under-transfer savings.

Threading:
- Build / filter are pure functions. No state. Thread-safe.
"""

from __future__ import annotations

import logging
import struct
from typing import Iterable

log = logging.getLogger(__name__)


# 4-byte length prefix on the wire so the encoded Bloom can be framed
# without parsing the internal header.
_WIRE_LEN_PREFIX = "<I"


try:
    from one_link_native import bloom as _native_bloom  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_bloom, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_bloom = None  # type: ignore[assignment]
    log.info(
        "one_link_native.bloom not installed (%s); Bloom-init handshake "
        "unavailable. Daemons fall back to manifest-then-chunks.",
        exc,
    )


# Production-tuned false-positive target.
#
# Sizing math:
# - 5% FP, 1000 chunks: Bloom ~600 bytes. Best wire-byte savings but
#   ~50 chunks/transfer would be mistakenly skipped if the sender
#   trusted the Bloom alone.
# - 0.1% FP, 1000 chunks: Bloom ~1800 bytes. ~1 chunk/transfer false-
#   positive. Compatible with the integrity-check-and-recover
#   correction round.
# - 0.001% FP, 1000 chunks: Bloom ~3700 bytes. Effectively zero
#   false positives; full Bloom-as-canonical safe without
#   correction rounds.
#
# We pick 0.1% as the production default: rare enough false positives
# that the recovery round fires <1×/transfer on average, small enough
# Bloom to still win vs FILE_WANTS at the 1000-chunk scale (1800
# bytes Bloom vs ~6400 bytes wants list at 80% known).
#
# The measurement script `scripts/bloom_init_savings_measure.py`
# sweeps multiple FP rates; operators can re-tune via the
# ``ONE_LINK_BLOOM_FP_RATE`` env var.
PRODUCTION_FP_RATE = 0.001


def _resolve_fp_rate(override: float | None) -> float:
    """Pick the FP rate to use. Caller's override wins; otherwise
    consult ONE_LINK_BLOOM_FP_RATE env var; final fallback is
    PRODUCTION_FP_RATE."""
    if override is not None:
        return override
    import os

    env = os.environ.get("ONE_LINK_BLOOM_FP_RATE")
    if env:
        try:
            v = float(env)
            if 0 < v < 1:
                return v
        except ValueError:
            pass
    return PRODUCTION_FP_RATE


def bloom_honor_enabled() -> bool:
    """True when production daemons should drop FILE_WANTS frames in
    favour of Bloom-only mode for BLOOM_INIT_V1-advertising peers.

    Default OFF for safety: production cutover happens by setting
    ``ONE_LINK_BLOOM_HONOR=1`` on the daemon. Until then both wire
    formats fly and operators monitor disagreement / savings telemetry
    in ``/api/metrics``.
    """
    import os

    return os.environ.get("ONE_LINK_BLOOM_HONOR", "0") in ("1", "true", "yes")


def build_receiver_bloom(
    known_chunk_ids: Iterable[bytes],
    *,
    target_fp_rate: float | None = None,
) -> bytes:
    """Build the receiver-side Bloom of locally-held chunk IDs and
    return its wire-encoded form (4-byte length prefix + encoded
    Bloom body). The receiver sends this back to the sender on
    transfer offer; the sender filters its manifest against it.

    Raises ``RuntimeError`` if the native crate isn't installed —
    callers should branch on :data:`HAS_NATIVE` first.
    """
    if not HAS_NATIVE:
        raise RuntimeError(
            "Bloom-init requires one_link_native.bloom; not installed"
        )
    ids = list(known_chunk_ids)
    # Even an empty filter is valid (no chunks known → sender ships
    # everything). Sizing at n=0 would be degenerate; clamp to n=1 so
    # the encoded Bloom is well-formed.
    n = max(len(ids), 1)
    fp = _resolve_fp_rate(target_fp_rate)
    bf = _native_bloom.Bloom(n, fp)
    for cid in ids:
        bf.insert(cid)
    encoded = bf.encode()
    prefix = struct.pack(_WIRE_LEN_PREFIX, len(encoded))
    return prefix + encoded


def decode_receiver_bloom(wire_bytes: bytes):
    """Decode a receiver-Bloom from the wire. Returns the native
    Bloom object (queryable via ``.contains(chunk_id)``).

    Raises ``ValueError`` on a malformed wire frame.
    Raises ``RuntimeError`` if the native crate isn't installed.
    """
    if not HAS_NATIVE:
        raise RuntimeError(
            "Bloom-init requires one_link_native.bloom; not installed"
        )
    if len(wire_bytes) < struct.calcsize(_WIRE_LEN_PREFIX):
        raise ValueError(
            f"Bloom-init wire frame too short: {len(wire_bytes)} bytes"
        )
    (length,) = struct.unpack_from(_WIRE_LEN_PREFIX, wire_bytes, 0)
    body = wire_bytes[struct.calcsize(_WIRE_LEN_PREFIX):]
    if len(body) != length:
        raise ValueError(
            f"Bloom-init wire frame length mismatch: "
            f"prefix says {length}, got {len(body)} bytes"
        )
    return _native_bloom.Bloom.decode(body)


def filter_manifest_against_bloom(
    manifest_chunk_ids: Iterable[bytes],
    receiver_bloom,
) -> list[bytes]:
    """Return the subset of manifest chunk_ids that the receiver does
    NOT appear to have (false positives mean we might skip a chunk
    the receiver actually doesn't have; that's the design trade-off
    documented at module top).

    The sender calls this after receiving the receiver's Bloom and
    iterating its outgoing manifest. Resulting list is the "true
    delta" to transmit.
    """
    out: list[bytes] = []
    for cid in manifest_chunk_ids:
        # Skip chunks the Bloom says the receiver has. False positives
        # (chunk is reported as present but isn't) cause that chunk
        # to be missed; the receiver re-requests it after the
        # Bloom-init batch completes (via the existing
        # MANIFEST_WANTS / FILE_CHUNK path).
        if not receiver_bloom.contains(cid):
            out.append(cid)
    return out


def measure_savings(
    *,
    manifest_size: int,
    bloom_wire_bytes: int,
    missing_chunk_count: int,
    chunk_id_bytes: int = 32,
) -> dict[str, float | int]:
    """Estimate bytes-on-wire savings for a given Bloom-init exchange.

    `bloom_wire_bytes` already includes the 4-byte length prefix.

    Returns a diagnostic dict surfaced via /api/metrics or daemon
    logs. The savings field is the ratio of bytes saved over a
    full-manifest baseline:

        baseline = manifest_size * chunk_id_bytes
        actual = bloom_wire_bytes + missing_chunk_count * chunk_id_bytes
        savings = (baseline - actual) / baseline
    """
    baseline = manifest_size * chunk_id_bytes
    actual = bloom_wire_bytes + missing_chunk_count * chunk_id_bytes
    if baseline <= 0:
        return {
            "baseline_bytes": 0,
            "actual_bytes": actual,
            "savings_bytes": -actual,
            "savings_fraction": 0.0,
        }
    savings = baseline - actual
    return {
        "baseline_bytes": baseline,
        "actual_bytes": actual,
        "savings_bytes": savings,
        "savings_fraction": savings / baseline,
    }
