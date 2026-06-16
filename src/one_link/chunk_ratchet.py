"""Per-chunk forward-secret ratchet (ADR-0020, Phase C item #6).

Phase E coupling: when the coherence field is available, the ratchet
manager can query a per-peer **rotation cadence advisory** via
``field_driven_rotation_cadence`` — peers in low-coherence wells get a
faster recommended rotation rate per byte than peers in stable
neighbourhoods. The advisory is consumed by the transfer layer when
deciding chunk size / re-key cadence, but the ratchet chain itself
still advances one step per chunk as before. The cadence is an
advisory ceiling, not a mandate.



This module extends ``double_ratchet.py`` from per-message to per-chunk
forward secrecy. Each ``ChunkRatchet`` is bootstrapped from the
channel's existing Double Ratchet root key (or any 32-byte shared
secret), then advances one step per chunk transferred. Compromise of
one chunk key reveals one chunk and nothing earlier.

The native implementation (``ol_ratchet``) is a straight-line
BLAKE3-keyed symmetric chain:

    ck_0  = derive_key("ol-ratchet-chain-init-v1",  shared_secret)
    mk_n  = derive_key("ol-ratchet-message-key-v1", ck_n)
    ck_n+1 = derive_key("ol-ratchet-chain-step-v1", ck_n)

Per stress-test #1's coupling requirement, the same primitive is also
the canonical chunk-level key source for the chunk_store path. The
double_ratchet's per-message keys remain authoritative for channel
text messages.

Typical chunk-store integration:

    sender = ChunkRatchet.from_shared_secret(kem_shared_secret)
    for chunk in chunks:
        key, idx = sender.next_key()
        ciphertext = aead.encrypt_chunk(key, chunk_id=H(chunk), plaintext=chunk)
        send((idx, ciphertext))

    receiver = ChunkRatchet.from_shared_secret(kem_shared_secret)
    skipped = receiver.skipped_store()
    for (idx, ciphertext) in incoming:
        key = receiver.key_at(idx, skipped=skipped)
        plaintext = aead.decrypt_chunk(key, chunk_id=H(plaintext), ...)
"""

from __future__ import annotations


from . import ratchet_native


class ChunkRatchet:
    """Per-chunk forward-secret key source backed by ``ol_ratchet``.

    See module docstring. Each instance is one direction of the
    chunk-key chain (sender and receiver hold matched instances)."""

    def __init__(self) -> None:
        if not ratchet_native.HAS_NATIVE:
            raise RuntimeError(
                "ChunkRatchet requires one_link_native.ratchet (ADR-0020); "
                "build via `cd native && maturin develop --release`"
            )
        self._chain = None  # set by from_shared_secret
        self._next_idx: int = 0

    @classmethod
    def from_shared_secret(cls, shared_secret: bytes) -> "ChunkRatchet":
        """Bootstrap from a 32-byte shared secret (typically the
        channel's KEM output or DR root key)."""
        if len(shared_secret) != 32:
            raise ValueError(
                f"shared_secret must be 32 bytes, got {len(shared_secret)}"
            )
        inst = cls()
        inst._chain = ratchet_native.from_shared_secret(shared_secret)
        return inst

    def next_key(self) -> tuple[bytes, int]:
        """Advance one step and return ``(chunk_key, chunk_idx)``. The
        index is monotonically increasing; callers must transmit it on
        the wire so the receiver can re-derive (or look up a skipped
        key)."""
        # ES-18: explicit raise, not assert (python -O strips asserts).
        if self._chain is None:
            raise RuntimeError("ChunkRatchet not initialized")
        key = bytes(self._chain.next_message_key())
        idx = self._next_idx
        self._next_idx += 1
        return key, idx

    def peek_at_current(self) -> bytes:
        """Return the chunk-key at the CURRENT index without
        advancing. Used by the receiver to derive a key in-order
        before committing the advance."""
        # ES-18: explicit raise, not assert (python -O strips asserts).
        if self._chain is None:
            raise RuntimeError("ChunkRatchet not initialized")
        return bytes(self._chain.peek_message_key(self._next_idx))

    def skipped_store(self, cap: int = 1024):
        """Build a bounded skipped-key cache for out-of-order receive.
        Use when a chunk index ``n+k`` arrives before ``n``."""
        return ratchet_native.skipped_store(cap)

    def key_at(self, target_idx: int, *, skipped=None) -> bytes:
        """Derive the chunk-key for ``target_idx``. If ``target_idx``
        is the current step, advance and return. If it's ahead,
        derive intermediate keys and stash them in ``skipped`` (if
        provided) for later lookup. If ``target_idx`` is behind,
        look it up in ``skipped`` (raises KeyError if absent)."""
        # ES-18: explicit raise, not assert (python -O strips asserts).
        if self._chain is None:
            raise RuntimeError("ChunkRatchet not initialized")
        if target_idx == self._next_idx:
            key, _ = self.next_key()
            return key
        if target_idx > self._next_idx:
            # Skip ahead; cache intermediate keys.
            while self._next_idx < target_idx:
                k, idx = self.next_key()
                if skipped is not None:
                    skipped.insert(idx, k)
            return self.next_key()[0]
        # Behind: look up in skipped store.
        if skipped is None:
            raise KeyError(
                f"chunk_idx {target_idx} is behind current {self._next_idx}; "
                "a skipped-key store is required for out-of-order receive"
            )
        key = skipped.take(target_idx)
        if key is None:
            raise KeyError(f"chunk_idx {target_idx} not in skipped store")
        return bytes(key)

    @property
    def current_index(self) -> int:
        """Index of the next chunk-key the chain will produce."""
        return self._next_idx


def derive_chunk_key(shared_secret: bytes, chunk_idx: int) -> bytes:
    """Convenience: derive a single chunk-key at ``chunk_idx`` from
    ``shared_secret``. NOT for production hot-path use — every call
    re-derives from index 0. Useful for tests and ad-hoc derivation."""
    r = ChunkRatchet.from_shared_secret(shared_secret)
    for _ in range(chunk_idx):
        r.next_key()
    return r.next_key()[0]


def field_driven_rotation_cadence(
    field: list[float],
    *,
    baseline_bytes: int = 1_000_000,
    mu_max: float = 4.0,
    power: float = 2.0,
) -> list[tuple[int, float, int]]:
    """Per-peer rotation-cadence advisory derived from a coherence
    field snapshot.

    Returns a list of ``(peer_index, multiplier, bytes_between_rotations)``
    sorted in input order. Peers in low-coherence wells get a higher
    ``multiplier`` and a smaller ``bytes_between_rotations`` — the
    ratchet manager should rotate keys / shrink chunk sizes faster
    on those edges.

    Implementation: thin wrapper around
    ``coherence_field_native.rotation_cadence_multiplier``. Returns
    an empty list when the native crate isn't available (callers
    treat as "no recommendation; use baseline cadence").

    Daemon usage:

    .. code-block:: python

        field = cf.solve_helmholtz(graph, d, gamma, source)["field"]
        for peer, mult, btw in field_driven_rotation_cadence(field):
            # btw is the recommended bytes-between-rotations for `peer`
            # in the swarm-wide peer index space.
            transfer_brain.set_rotation_cadence(peer, btw)
    """
    try:
        from one_link import coherence_field_native as _cf
    except ImportError:
        return []
    if not _cf.HAS_NATIVE:
        return []
    return _cf.rotation_cadence_multiplier(
        field, baseline_bytes, mu_max=mu_max, power=power
    )
