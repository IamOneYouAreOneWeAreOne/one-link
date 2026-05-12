"""Adapter for the Coherence Mesh F1.4 channel-reciprocity primitive
(``ol_proximity_pair`` via ``one_link_native``).

Per COHERENCE_MESH_PLAN.md Phase F1.4 — physics-layer Factor-2 pair
trust. Two devices in the same physical environment derive a
matching 256-bit secret from their shared observations WITHOUT
ever transmitting the secret.

Typical daemon usage (alongside the QR-scanned Factor-1 secret):

.. code-block:: python

    from one_link import proximity_pair_native as pp

    # During pair bootstrap, both daemons scan the local network
    # environment (WiFi APs / BLE adverts / mDNS broadcasts). The
    # scanner produces a byte vector summarising the observation.
    my_obs = wifi_scanner.scan_and_serialize()  # platform-specific

    # Bob ships its syndrome over the public channel (already
    # bootstrap-encrypted by the Factor-1 QR-handshake).
    bob_syndrome = pp.block_syndrome(my_bits)

    # Alice runs the pipeline.
    salt = transcript_hash_from_qr_scan  # 32 bytes
    factor2_secret = pp.derive_factor2_secret(
        my_observations=my_obs,
        peer_syndrome=bob_syndrome,
        salt=salt,
    )

    # Mix Factor-1 + Factor-2 into the Double Ratchet seed.
    chain_key = blake3.derive_key(factor1_secret + factor2_secret)

Honest scope notes:
- The currently-shipped reconciliation is single-pass parity-flip,
  good for ~93-97% bit agreement. Byte-identical keys require real
  CASCADE bisection (Brassard-Salvail 1994), tracked as F1.4-polish
  next ship.
- The scanner (`wifi_scanner` above) is daemon-side platform code
  and not part of this adapter — this adapter exposes only the
  cryptographic pipeline.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import proximity_pair as _native_pp  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    AMPLIFIED_KEY_BYTES: int = _native_pp.AMPLIFIED_KEY_BYTES
    OBSERVATION_BYTES_DEFAULT: int = _native_pp.OBSERVATION_BYTES_DEFAULT
    GUARD_BAND_DEFAULT: float = _native_pp.GUARD_BAND_DEFAULT
    SYNDROME_BLOCK_BITS_DEFAULT: int = _native_pp.SYNDROME_BLOCK_BITS_DEFAULT
    CASCADE_PASSES_DEFAULT: int = _native_pp.CASCADE_PASSES_DEFAULT
    HAMMING_CODEWORD_BITS: int = _native_pp.HAMMING_CODEWORD_BITS
    HAMMING_DATA_BITS: int = _native_pp.HAMMING_DATA_BITS
    HAMMING_PARITY_BITS: int = _native_pp.HAMMING_PARITY_BITS
except ImportError as exc:
    HAS_NATIVE = False
    _native_pp = None  # type: ignore[assignment]
    AMPLIFIED_KEY_BYTES = 32
    OBSERVATION_BYTES_DEFAULT = 128
    GUARD_BAND_DEFAULT = 0.10
    SYNDROME_BLOCK_BITS_DEFAULT = 8
    CASCADE_PASSES_DEFAULT = 4
    HAMMING_CODEWORD_BITS = 127
    HAMMING_DATA_BITS = 120
    HAMMING_PARITY_BITS = 7
    log.info(
        "one_link_native.proximity_pair not installed (%s); channel-"
        "reciprocity Factor-2 pair-trust unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


def quantize_observations(
    observations: bytes,
    *,
    min_bytes: int = OBSERVATION_BYTES_DEFAULT,
    guard_band: float = GUARD_BAND_DEFAULT,
) -> bytes:
    """Quantize an observation byte vector to a packed bit string
    (one bit per byte, value 0 or 1). Observations inside the guard
    band are skipped."""
    _require_native()
    return _native_pp.quantize_observations(
        bytes(observations), int(min_bytes), float(guard_band)
    )


def block_syndrome(
    bits: bytes, *, block_bits: int = SYNDROME_BLOCK_BITS_DEFAULT
) -> bytes:
    """Compute the block-XOR-parity syndrome of `bits`."""
    _require_native()
    return _native_pp.block_syndrome(bytes(bits), int(block_bits))


def reconcile_with_syndrome(
    my_bits: bytes,
    peer_syndrome: bytes,
    *,
    block_bits: int = SYNDROME_BLOCK_BITS_DEFAULT,
) -> bytes:
    """One-pass reconciliation. Honest scope: doesn't drive error
    rate to zero — use `multi_pass_reconcile` for better results
    or the (future) real bisection in F1.4-polish."""
    _require_native()
    return _native_pp.reconcile_with_syndrome(
        bytes(my_bits), bytes(peer_syndrome), int(block_bits)
    )


def multi_pass_syndromes(
    my_bits: bytes,
    *,
    block_bits: int = SYNDROME_BLOCK_BITS_DEFAULT,
    passes: int = CASCADE_PASSES_DEFAULT,
    permutation_seed: int = 0,
) -> list[bytes]:
    """Generate multi-pass syndromes for shipping to the peer."""
    _require_native()
    return _native_pp.multi_pass_syndromes(
        bytes(my_bits),
        int(block_bits),
        int(passes),
        int(permutation_seed),
    )


def multi_pass_reconcile(
    my_bits: bytes,
    peer_syndromes: list[bytes],
    *,
    block_bits: int = SYNDROME_BLOCK_BITS_DEFAULT,
    passes: int = CASCADE_PASSES_DEFAULT,
    permutation_seed: int = 0,
) -> bytes:
    """Multi-pass reconciliation driver."""
    _require_native()
    return _native_pp.multi_pass_reconcile(
        bytes(my_bits),
        [bytes(s) for s in peer_syndromes],
        int(block_bits),
        int(passes),
        int(permutation_seed),
    )


def hamming_parity(bits: bytes) -> bytes:
    """Compute Hamming(127,120) parity bits for `bits`.

    Each 120-bit block produces 7 parity bytes. Last partial block
    is zero-padded internally. Output length = ceil(len/120) * 7.
    """
    _require_native()
    return _native_pp.hamming_parity(bytes(bits))


def hamming_reconcile(my_bits: bytes, peer_parity: bytes) -> bytes:
    """One-pass Hamming(127,120) SEC reconciliation.

    Mathematically corrects 1 bit error per 120-bit block. Multi-
    error blocks need SECDED + multi-pass permutation (F1.4-polish v2).
    """
    _require_native()
    return _native_pp.hamming_reconcile(bytes(my_bits), bytes(peer_parity))


def privacy_amplify(reconciled_bits: bytes, *, salt: bytes) -> bytes:
    """BLAKE3-keyed hash reconciled bits to 32 bytes. Salt must be
    32 bytes; both sides must use the same salt."""
    _require_native()
    return _native_pp.privacy_amplify(bytes(reconciled_bits), bytes(salt))


def derive_factor2_secret(
    *,
    my_observations: bytes,
    peer_syndrome: bytes,
    salt: bytes,
    min_bytes: int = OBSERVATION_BYTES_DEFAULT,
    guard_band: float = GUARD_BAND_DEFAULT,
    block_bits: int = SYNDROME_BLOCK_BITS_DEFAULT,
) -> bytes:
    """One-shot full pipeline: quantize -> reconcile (one-pass) ->
    privacy amplify. Returns the 32-byte Factor-2 secret."""
    _require_native()
    return _native_pp.derive_factor2_secret(
        bytes(my_observations),
        bytes(peer_syndrome),
        bytes(salt),
        int(min_bytes),
        float(guard_band),
        int(block_bits),
    )


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.proximity_pair required for channel-"
            "reciprocity Factor-2 pair-trust but not installed; "
            "build via `cd native && maturin develop --release`."
        )
