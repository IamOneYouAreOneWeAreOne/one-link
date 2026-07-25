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
        streams = tr.shamir_split_secure(master_seed, k=3, n=5)
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

        import secrets
        from blake3 import blake3

        # The public field output is context, not secret entropy. Generate an
        # independent secret and use the canonical field bytes only as keyed-KDF
        # input. Keep binding_key/witness separate from the masked shares.
        field_state = field_snapshot_manager.snapshot()
        field_context = canonicalize_field_context(field_state)
        binding_key = secrets.token_bytes(32)
        field_seed = blake3(field_context, key=binding_key).digest()
        scores = [field_snapshot_manager.field_score_for_peer(p) for p in contacts]
        witness = tr.FieldWitness(field_seed, scores, epoch_ns)

        # Mint with the witness.
        masked = tr.field_bound_split_secure(master_seed, k=3, n=5, witness=witness)

        # Recover: requires the witness AND >= K masked shares.
        recovered = tr.field_bound_reconstruct(xs, ys, share_indices, k, witness)

In Mode 2, the field-binding key is a separate defense-in-depth factor. The
Shamir threshold remains the primary protection; the witness must never be
stored beside the masked shares.
"""

from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)


class ThresholdRecoveryCapabilityError(RuntimeError):
    """The installed native extension cannot satisfy its declared ABI."""


_REQUIRED_NATIVE_CALLABLES = (
    "shamir_split",
    "shamir_split_secure",
    "shamir_reconstruct",
    "shamir_max_participants",
    "shamir_params_valid",
    "field_bound_split",
    "field_bound_split_secure",
    "field_bound_reconstruct",
)
_FALLBACK_POLICY_ENV = "ONE_LINK_THRESHOLD_RECOVERY_PYTHON_FALLBACK"


def _missing_native_abi(module: Any) -> tuple[str, ...]:
    """Return the full missing/non-callable ABI set for one candidate module."""

    missing = [
        name
        for name in _REQUIRED_NATIVE_CALLABLES
        if not callable(getattr(module, name, None))
    ]
    witness = getattr(module, "FieldWitness", None)
    if not callable(witness):
        missing.append("FieldWitness")
    elif not callable(getattr(witness, "placeholder", None)):
        missing.append("FieldWitness.placeholder")
    return tuple(missing)


def python_fallback_permitted() -> bool:
    """Return the explicit compatibility policy for reviewed Python Shamir.

    The existing product contract permits the CSPRNG-backed pure-Python
    implementation when native code is absent.  Hardened deployments can set
    the variable to ``0``/``false``/``no`` and receive a capability error
    instead.  Unknown values fail closed rather than silently weakening policy.
    """

    raw = os.environ.get(_FALLBACK_POLICY_ENV, "1").strip().casefold()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    log.error("invalid %s value %r; Python fallback disabled", _FALLBACK_POLICY_ENV, raw)
    return False


_NATIVE_MISSING_ABI: tuple[str, ...] = ()
_NATIVE_IMPORT_ERROR = ""
try:
    from one_link_native import threshold_recovery as _native_tr  # type: ignore[import-not-found,attr-defined]

    _NATIVE_MISSING_ABI = _missing_native_abi(_native_tr)
    HAS_NATIVE: bool = not _NATIVE_MISSING_ABI
    if _NATIVE_MISSING_ABI:
        log.warning(
            "one_link_native.threshold_recovery has an incomplete/stale ABI "
            "(missing: %s); native threshold recovery disabled",
            ", ".join(_NATIVE_MISSING_ABI),
        )
except ImportError as exc:
    HAS_NATIVE = False
    _native_tr = None  # type: ignore[assignment]
    _NATIVE_IMPORT_ERROR = str(exc)
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

    ``seed`` selects deterministic coefficient generation and is intended
    for test vectors and migrations. Production code should call
    :func:`shamir_split_secure`; a 64-bit seed cannot provide a modern
    cryptographic security margin.

    Raises ``ValueError`` on invalid (k, n).
    """
    _require_native()
    result: list[bytes] = _native_tr.shamir_split(
        secret, int(k), int(n), int(seed)
    )
    return result


def shamir_split_secure(secret: bytes, *, k: int, n: int) -> list[bytes]:
    """Split using fresh operating-system CSPRNG entropy.

    This is the production entry point. Randomness is generated inside the
    native boundary and is never returned to Python.
    """
    _require_native()
    result: list[bytes] = _native_tr.shamir_split_secure(
        bytes(secret), int(k), int(n)
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


def split_compat(
    secret: bytes, *, threshold: int, num_shares: int
) -> list[tuple[int, bytes]]:
    """Native-fast Shamir split that returns share tuples compatible
    with `one_link.threshold.Share` (which has `.x` and `.y`).

    Returns a list of `(x, y_bytes)` tuples where `x` is 1..num_shares
    and `y_bytes` has length `len(secret)`. Callers can construct
    `Share(x=t[0], y=t[1])` from the result if they need the dataclass.

    Falls back to the pure-Python `one_link.threshold` module if the
    native extension isn't installed.
    """
    if not HAS_NATIVE:
        if not python_fallback_permitted():
            _require_native()
        from one_link import threshold as _py_threshold

        shares = _py_threshold.split(
            secret=secret, threshold=threshold, num_shares=num_shares
        )
        return [(s.x, s.y) for s in shares]
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    if len(secret) == 0:
        raise ValueError("secret must be at least 1 byte")
    if not (2 <= threshold <= num_shares <= 255):
        raise ValueError(
            f"invalid threshold={threshold} / num_shares={num_shares}; "
            f"need 2 <= threshold <= num_shares <= 255"
        )
    streams = shamir_split_secure(bytes(secret), k=threshold, n=num_shares)
    return [(i + 1, streams[i]) for i in range(num_shares)]


def combine_compat(shares: list[tuple[int, bytes]], *, threshold: int) -> bytes:
    """Native-fast Shamir combine. `shares` is a list of (x, y_bytes)
    tuples from `split_compat`. Falls back to pure-Python if native is
    unavailable.

    The caller must supply at least `threshold` shares; extra shares
    are accepted (we drop to the first `threshold` for the LU solve).
    """
    if not HAS_NATIVE:
        if not python_fallback_permitted():
            _require_native()
        from one_link import threshold as _py_threshold

        return _py_threshold.combine(
            [_py_threshold.Share(x=x, y=y) for x, y in shares]
        )
    if len(shares) < threshold:
        raise ValueError(
            f"need at least {threshold} shares, got {len(shares)}"
        )
    # Native takes the first `threshold` shares.
    selected = shares[:threshold]
    xs = [int(x) for x, _ in selected]
    ys = [bytes(y) for _, y in selected]
    return shamir_reconstruct(xs, ys, k=threshold)


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


def field_bound_split_secure(
    secret: bytes,
    *,
    k: int,
    n: int,
    witness: Any,
) -> list[bytes]:
    """Production field-bound split using native OS CSPRNG entropy."""
    _require_native()
    result: list[bytes] = _native_tr.field_bound_split_secure(
        bytes(secret), int(k), int(n), witness
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
        detail = (
            f"installed extension is incomplete (missing: {', '.join(_NATIVE_MISSING_ABI)})"
            if _NATIVE_MISSING_ABI
            else f"extension import failed ({_NATIVE_IMPORT_ERROR or 'not installed'})"
        )
        raise ThresholdRecoveryCapabilityError(
            "complete one_link_native.threshold_recovery ABI required by policy; "
            f"{detail}. Build/install the matching release via "
            "`cd native && maturin develop --release`."
        )
