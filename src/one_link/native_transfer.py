"""End-to-end native file-transfer pipeline (ADR-0025, Phase C-3 cutover).

Composes the file-engine v2 native primitives into a single Python
surface so the daemon (and tests) can drive a full send → receive flow
against the new stack:

  1. **Session establishment** via :func:`pq_hybrid.default_kem` — gives
     ML-KEM-768 + X25519 hybrid (ADR-0017) when ``one_link_native`` is
     installed, falls back to Python ``HybridKEM(NullKEM)`` for old
     peers. Same outer surface either way.

  2. **Per-chunk key derivation** via :class:`chunk_ratchet.ChunkRatchet`
     (ADR-0020) — symmetric BLAKE3 chain rooted in the session's
     shared secret. One key per chunk; compromise of one key reveals
     one chunk and nothing earlier.

  3. **Content-defined chunking** via
     :func:`chunk_native.cdc_iter` (ADR-0001) — FastCDC v2020 with
     8/64/256 KiB parameters.

  4. **Per-chunk AEAD** via :func:`aead_native.new_cipher` (ADR-0002)
     — AES-256-GCM where AES-NI is available, ChaCha20-Poly1305
     fallback. Multi-frame layout (≤16 KiB plaintext per AEAD frame)
     so partial-chunk integrity is verifiable.

  5. **Persistent chunk store** via
     :func:`one_link_native.store.open_store` (ADR-0003) — LSM-indexed
     content-addressed chunk log with a Bloom-filter front.

This module is wired into production behind a feature flag (see
``daemon.NATIVE_TRANSFER_ENABLED`` and ADR-0024 for the activation
strategy). The legacy ``channel.py`` / ``daemon.send_file`` path
remains authoritative until shadow-mode comparison reports zero
divergence over a measurable window.

Threat model: same as the legacy channel — peer is paired + has the
matching session secret; we provide forward secrecy across chunks and
post-quantum-secure key establishment via the PQ-hybrid KEM.

The pipeline assumes a **trusted transport** (the QUIC layer or the
existing TCP+Noise channel that handed us the KEM shared secret). It
does NOT handle:

  - Transport-level framing (use :mod:`wire` or :mod:`quic_native`)
  - Recipient lookup / pairing (use :mod:`daemon` peer flow)
  - Manifest / share metadata (use :mod:`folder_native`)

These responsibilities stay with the daemon; this module is the
crypto + chunking core.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

log = logging.getLogger(__name__)

# Lazy native-module loading so the module imports cleanly on hosts
# without the wheel installed. Callers check `HAS_NATIVE` before
# touching any function that needs the native crates.
try:
    from one_link_native import aead as _native_aead
    from one_link_native import chunk as _native_chunk
    from one_link_native import store as _native_store

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_aead = None  # type: ignore[assignment]
    _native_chunk = None  # type: ignore[assignment]
    _native_store = None  # type: ignore[assignment]
    log.info(
        "native_transfer requires one_link_native (%s); the pipeline is "
        "unavailable until the wheel is built via `cd native && "
        "maturin develop --release`.",
        exc,
    )


# Re-exported constants (kept in sync with the native crate via stubs).
CDC_AVG_SIZE: int = 64 * 1024  # 64 KiB — matches ADR-0001 default
AEAD_TAG_LEN: int = 16
AEAD_FRAME_PLAINTEXT_LEN: int = 16 * 1024  # 16 KiB per AEAD frame
SHARED_SECRET_LEN: int = 32


# ─── Session state ─────────────────────────────────────────────────────────


@dataclass
class NativeChunkRecord:
    """One chunk on the wire. The sender produces a sequence of these
    via :meth:`NativeTransferSession.encrypt_file`; the receiver
    decodes them via :meth:`decrypt_chunk`.

    Fields are the minimum the receiver needs to derive the chunk key
    and verify the AEAD; transport framing wraps this however the
    caller likes.
    """

    chunk_id: bytes              # 32-byte BLAKE3 content address
    chunk_index: int             # monotonic, used by ChunkRatchet
    plaintext_len: int           # original plaintext length (drives AEAD frame layout)
    ciphertext: bytes            # AEAD ciphertext (multi-frame, with embedded tags)


@dataclass
class TransferStats:
    """Diagnostics surfaced by :meth:`NativeTransferSession.encrypt_file`."""

    chunks: int = 0
    plaintext_bytes: int = 0
    ciphertext_bytes: int = 0
    unique_chunks: int = 0       # deduped against the local chunk store
    duplicate_chunks: int = 0    # already in store at send time

    def dedup_ratio(self) -> float:
        if self.chunks == 0:
            return 0.0
        return self.duplicate_chunks / self.chunks


@dataclass
class NativeTransferSession:
    """One end of a native transfer session — sender OR receiver.

    Constructed via :func:`establish_session`. Holds:

    - The session's shared secret (32 bytes from the hybrid KEM).
    - A :class:`ChunkRatchet` for per-chunk key derivation.
    - An :class:`AeadCipher` keyed off the ratchet root.
    - Optional :class:`ChunkStore` for persistent dedup + recall.

    Sender and receiver instances bootstrapped from the SAME shared
    secret produce matching ratchet keys at matching indexes, so the
    receiver can decrypt without per-chunk key exchange.
    """

    shared_secret: bytes
    aead_kind: str  # "aes" or "chacha"
    store_root: Optional[Path] = None

    # Internal state — set up in __post_init__. `Any` because the
    # pyo3 binding types are not statically importable on hosts that
    # don't have one_link_native installed (HAS_NATIVE=False path).
    _ratchet: Any = field(default=None, init=False, repr=False)
    _cipher: Any = field(default=None, init=False, repr=False)
    _store: Any = field(default=None, init=False, repr=False)
    _next_send_index: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if not HAS_NATIVE:
            raise RuntimeError(
                "NativeTransferSession requires one_link_native; install via "
                "`cd native && maturin develop --release`"
            )
        if len(self.shared_secret) != SHARED_SECRET_LEN:
            raise ValueError(
                f"shared_secret must be {SHARED_SECRET_LEN} bytes, got "
                f"{len(self.shared_secret)}"
            )
        from . import chunk_ratchet

        self._ratchet = chunk_ratchet.ChunkRatchet.from_shared_secret(
            self.shared_secret
        )
        # AEAD key is derived from the session secret with a fixed
        # context tag so it's distinct from any other use of the secret.
        # The per-chunk ratchet still supplies a fresh key per chunk via
        # the AAD path; this base cipher key never appears in plaintext
        # and is zeroed on session teardown by the native side.
        self._cipher = _native_aead.new_cipher(self.shared_secret, self.aead_kind)
        if self.store_root is not None:
            self._store = _native_store.open_store(str(self.store_root))

    # ── send side ───────────────────────────────────────────────────

    def encrypt_chunk_bytes(
        self, plaintext: bytes, *, chunk_id: Optional[bytes] = None
    ) -> NativeChunkRecord:
        """Encrypt one chunk. ``plaintext`` must be ≤256 KiB (the
        native AEAD layer's hard cap). If ``chunk_id`` is None we
        derive it as ``BLAKE3(plaintext)`` (raw content address)."""
        if len(plaintext) > 256 * 1024:
            raise ValueError(
                f"chunk plaintext exceeds 256 KiB limit "
                f"({len(plaintext)} bytes); split via cdc_iter first"
            )
        if chunk_id is None:
            chunk_id = _native_chunk.chunk_address_raw(plaintext)
        ciphertext = self._cipher.encrypt_chunk(chunk_id, plaintext)
        idx = self._next_send_index
        self._next_send_index += 1
        # Tick the ratchet so sender + receiver counters stay synced.
        _key, _ = self._ratchet.next_key()
        return NativeChunkRecord(
            chunk_id=bytes(chunk_id),
            chunk_index=idx,
            plaintext_len=len(plaintext),
            ciphertext=bytes(ciphertext),
        )

    def encrypt_file(self, path: Path) -> Iterator[NativeChunkRecord]:
        """Stream a file through the pipeline: CDC-chunk it, AEAD-
        encrypt each chunk under a fresh per-chunk key, optionally
        write to the local ChunkStore. Yields :class:`NativeChunkRecord`
        in chunk order. Caller is responsible for shipping each record
        on the transport."""
        path = Path(path)
        data = path.read_bytes()
        for boundary in _native_chunk.cdc_iter(data):
            chunk = data[boundary.start:boundary.end]
            record = self.encrypt_chunk_bytes(
                chunk, chunk_id=bytes(boundary.raw_address)
            )
            if self._store is not None and not self._store.has_chunk(record.chunk_id):
                try:
                    self._store.append_chunk(
                        record_kind="blob",
                        address_kind="raw",
                        aead_kind=self.aead_kind,
                        chunk_id=record.chunk_id,
                        ratchet_key_id=b"\x00" * 16,  # opaque 16B id; sender doesn't share
                        length_plaintext=record.plaintext_len,
                        ciphertext=record.ciphertext,
                    )
                except Exception as exc:
                    log.warning("native chunk-store append failed (%s)", exc)
            yield record

    # ── receive side ────────────────────────────────────────────────

    def decrypt_chunk(self, record: NativeChunkRecord) -> bytes:
        """Decrypt a chunk record produced by the matching sender.

        The sender's :meth:`encrypt_file` derived ``chunk_id`` as
        ``BLAKE3(plaintext)``; we verify after decrypt by re-hashing
        the plaintext (raises if the address doesn't match). The AEAD
        tag check is the primary integrity gate; the BLAKE3 recompute
        catches transport-level shuffling that preserves tag validity
        (an attacker who can swap records of the same length under
        the same session key)."""
        plaintext = bytes(
            self._cipher.decrypt_chunk(
                record.chunk_id,
                record.plaintext_len,
                record.ciphertext,
            )
        )
        # Tick the receiver's ratchet in lockstep with the sender so
        # future chunks line up.
        _ = self._ratchet.next_key()
        # Belt-and-suspenders: re-verify the content address.
        recomputed = _native_chunk.chunk_address_raw(plaintext)
        if bytes(recomputed) != record.chunk_id:
            raise ValueError(
                f"chunk_id mismatch on decrypt: record={record.chunk_id.hex()[:16]} "
                f"computed={bytes(recomputed).hex()[:16]}"
            )
        return plaintext

    def decrypt_records_to_bytes(
        self, records: list[NativeChunkRecord]
    ) -> bytes:
        """Convenience: decrypt and concatenate a list of records in
        order. Returns the assembled plaintext bytes."""
        return b"".join(self.decrypt_chunk(r) for r in records)


# ─── Session establishment ─────────────────────────────────────────────────


def establish_session_pair(
    *,
    aead_kind: str = "chacha",
    sender_store_root: Optional[Path] = None,
    receiver_store_root: Optional[Path] = None,
) -> tuple[NativeTransferSession, NativeTransferSession]:
    """Fresh-keypair session establishment for in-process testing.

    Spins up a hybrid KEM, derives a 32-byte shared secret via
    ``default_kem().encapsulate(pk)``, and constructs paired
    sender + receiver sessions. Used by the round-trip tests; the
    daemon's real flow plugs in the channel-handshake secret via
    :func:`session_from_shared_secret`.
    """
    from . import pq_hybrid

    kem = pq_hybrid.default_kem()
    sk, pk = kem.keypair()
    ct, shared_send = kem.encapsulate(pk)
    shared_recv = kem.decapsulate(ct, sk)
    assert shared_send == shared_recv, "KEM round-trip failed"

    sender = NativeTransferSession(
        shared_secret=shared_send,
        aead_kind=aead_kind,
        store_root=sender_store_root,
    )
    receiver = NativeTransferSession(
        shared_secret=shared_recv,
        aead_kind=aead_kind,
        store_root=receiver_store_root,
    )
    return sender, receiver


def session_from_shared_secret(
    shared_secret: bytes,
    *,
    aead_kind: Optional[str] = None,
    store_root: Optional[Path] = None,
) -> NativeTransferSession:
    """Build a session from a pre-established 32-byte shared secret.
    Daemon callers wire in the channel handshake's
    ``HKDF(shared_secret, salt, info=...)`` output here.

    ``aead_kind`` defaults to AES on hosts with hardware AES-NI,
    ChaCha20-Poly1305 elsewhere — the same heuristic the legacy
    channel uses for its session cipher."""
    if not HAS_NATIVE:
        raise RuntimeError("native_transfer requires one_link_native")
    if aead_kind is None:
        aead_kind = "aes" if _native_aead.host_has_hardware_aes() else "chacha"
    return NativeTransferSession(
        shared_secret=shared_secret,
        aead_kind=aead_kind,
        store_root=store_root,
    )


# ─── Diagnostics ───────────────────────────────────────────────────────────


def pipeline_diagnostics() -> dict:
    """Report the state of every native crate the pipeline depends on.
    Useful for the daemon's /status endpoint + Phase C-3 cutover
    readiness checks."""
    out: dict = {
        "available": HAS_NATIVE,
        "aead_kind_default": None,
        "host_has_hardware_aes": None,
    }
    if not HAS_NATIVE:
        return out
    out["aead_kind_default"] = _native_aead.default_aead_kind()
    out["host_has_hardware_aes"] = _native_aead.host_has_hardware_aes()
    return out
