"""Adapter for the Coherence Mesh F1.1 threshold-recovery primitive
(``ol_threshold_recovery`` via ``one_link_native``).

Per COHERENCE_MESH_PLAN.md Phase F1.1. Sovereign identity-recovery via
Shamir(K, N) secret sharing over GF(2^8), with the alien-tech
coherence-field-binding layer that ties recovery to the swarm topology
at mint time.

Two usage modes:

1. **Plain Shamir** (works without a coherence-field deployment):

    .. code-block:: python

        from one_link import threshold_recovery_native as tr

        # Mint: split a 32-byte master seed across 5 trusted contacts.
        streams = tr.shamir_split(master_seed, k=3, n=5, seed=os.urandom(8))
        # Each `streams[i]` is the per-byte y-stream for share i+1.
        # Hand streams[i] (plus the x value i+1) to contact i.

        # Recover: collect any 3 of the 5 shares.
        xs = [1, 3, 5]            # the x values of the supplied shares
        ys = [streams[0], streams[2], streams[4]]
        master_seed = tr.shamir_reconstruct(xs, ys, k=3)

2. **Field-bound** (alien-tech defense in depth, requires Phase E):

    .. code-block:: python

        from one_link import threshold_recovery_native as tr
        from one_link import coherence_field_native as cf

        # Derive a 32-byte field seed from the current Helmholtz solve.
        field_state = field_snapshot_manager.snapshot()
        field_seed = ...  # 32 bytes from field_state.field via BLAKE3
        scores = [field_snapshot_manager.field_score_for_peer(p) for p in contacts]
        witness = tr.FieldWitness(field_seed, scores, epoch_ns)

        # Mint with the witness.
        masked = tr.field_bound_split(master_seed, k=3, n=5, seed=..., witness)

        # Recover: requires the witness AND >= K masked shares.
        recovered = tr.field_bound_reconstruct(xs, ys, share_indices, k, witness)

In Mode 2, an attacker holding all 5 raw masked shares but lacking
the field witness cannot reconstruct — the masked bytes are
information-theoretically independent of the secret without the
witness-derived OTPs.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

try:
    from one_link_native import threshold_recovery as _native_tr  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_tr = None  # type: ignore[assignment]
    log.info(
        "one_link_native.threshold_recovery not installed (%s); "
        "sovereign identity recovery unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


def shamir_split(
    secret: bytes, *, k: int, n: int, seed: int
) -> list[bytes]:
    """Split ``secret`` into ``n`` plain Shamir shares with threshold ``k``.

    Returns a list of ``n`` byte-streams; share i has length
    ``len(secret)`` and is the per-byte y-stream of the polynomial
    p_b(x = i + 1) for each secret byte b. Hand share i to contact i.

    ``seed`` is a 64-bit value the caller supplies for deterministic
    coefficient generation. Production callers should use a fresh
    cryptographic RNG sample.

    Raises ``ValueError`` on invalid (k, n).
    """
    _require_native()
    result: list[bytes] = _native_tr.shamir_split(
        secret, int(k), int(n), int(seed)
    )
    return result


def shamir_reconstruct(
    xs: list[int] | bytes, streams: list[bytes], *, k: int
) -> bytes:
    """Reconstruct the secret from at least ``k`` shares.

    ``xs`` is the x-value of each supplied share (1..255).
    ``streams`` is the parallel list of y-byte-streams.
    """
    _require_native()
    if isinstance(xs, bytes):
        xs_list = list(xs)
    else:
        xs_list = [int(x) for x in xs]
    streams_list = [bytes(s) for s in streams]
    result: bytes = _native_tr.shamir_reconstruct(
        bytes(xs_list), streams_list, int(k)
    )
    return result


def max_participants() -> int:
    """Maximum N the GF(2^8) scheme supports (255)."""
    _require_native()
    n: int = _native_tr.shamir_max_participants()
    return n


def params_valid(k: int, n: int) -> bool:
    """Are (k, n) within valid bounds?"""
    _require_native()
    ok: bool = _native_tr.shamir_params_valid(int(k), int(n))
    return ok


# ── Field-bound (alien-tech) surface ──────────────────────────────


def field_witness(
    field_seed: bytes,
    holder_scores: list[float],
    epoch_ns: int,
) -> Any:
    """Build a coherence-field witness.

    ``field_seed`` is 32 bytes derived from the coherence-field state at
    mint time (e.g., BLAKE3 hash of the Helmholtz solve output).
    ``holder_scores`` is the per-share field_score_for_peer value at
    mint time (each in [0, 1]). ``epoch_ns`` is a mint-time epoch so
    refresh ticks produce different masks.
    """
    _require_native()
    if len(field_seed) != 32:
        raise ValueError(
            f"field_seed must be 32 bytes, got {len(field_seed)}"
        )
    return _native_tr.FieldWitness(
        bytes(field_seed), list(holder_scores), int(epoch_ns)
    )


def placeholder_witness(n: int) -> Any:
    """No-op witness: field-binding becomes passthrough. Use when no
    coherence-field deployment is available so the same code path
    supports both alien-tech AND plain Shamir."""
    _require_native()
    return _native_tr.FieldWitness.placeholder(int(n))

def field_bound_split(
    secret: bytes,
    *,
    k: int,
    n: int,
    seed: int,
    witness: Any,
) -> list[bytes]:
    """Split with field-bound shares. Each share is XOR-masked with a
    witness-derived OTP."""
    _require_native()
    result: list[bytes] = _native_tr.field_bound_split(
        bytes(secret), int(k), int(n), int(seed), witness
    )
    return result


def field_bound_reconstruct(
    xs: list[int] | bytes,
    streams: list[bytes],
    share_indices: list[int],
    *,
    k: int,
    witness: Any,
) -> bytes:
    """Reconstruct from ``k`` field-bound shares + the witness.

    ``share_indices`` is the 0-based original index of each supplied
    share, so the right OTP is derived for unmasking.
    """
    _require_native()
    if isinstance(xs, bytes):
        xs_list = list(xs)
    else:
        xs_list = [int(x) for x in xs]
    result: bytes = _native_tr.field_bound_reconstruct(
        bytes(xs_list),
        [bytes(s) for s in streams],
        [int(i) for i in share_indices],
        int(k),
        witness,
    )
    return result


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.threshold_recovery required for sovereign "
            "identity recovery but not installed; build via "
            "`cd native && maturin develop --release`."
        )
