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
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

log = logging.getLogger(__name__)

# Lazy native-module loading so the module imports cleanly on hosts
# without the wheel installed. Callers check `HAS_NATIVE` before
# touching any function that needs the native crates.
_native_aead: Any = None
_native_chunk: Any = None
_native_store: Any = None
try:
    from one_link_native import aead as _native_aead  # type: ignore[attr-defined,no-redef]
    from one_link_native import chunk as _native_chunk  # type: ignore[attr-defined,no-redef]
    from one_link_native import store as _native_store  # type: ignore[attr-defined,no-redef]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
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

# 2026-05-21 audit T2-D: opt-in chunk_id re-verify after decrypt.
# Default OFF (the user's "no slowdowns" constraint). Operators in
# adversarial-peer environments flip ``ONE_LINK_VERIFY_CHUNK_HASH=1``
# to add a BLAKE3 pass per chunk that proves chunk_id == hash of
# plaintext, defeating cache-poisoning via AAD-only commitment.
_VERIFY_CHUNK_HASH: bool = (
    __import__("os").environ.get("ONE_LINK_VERIFY_CHUNK_HASH") == "1"
)

# 2026-05-22 audit Batch T: max indices retained in the
# replay-window seen-set. Tuned so that typical multi-file channels
# (a few-thousand chunks per file × <10 concurrent files) stay
# under the cap, but a long-lived channel doesn't accumulate unbounded
# memory. FIFO eviction (OrderedDict.popitem(last=False)) drops the
# OLDEST index — same audit-defense pattern as cap_store.seen_nonces
# (M11) so an adversary that spams replays can't grind-evict an honest
# index out of the set.
_REPLAY_WINDOW_MAX: int = 16384


class ReplayError(ValueError):
    """Raised when ``decrypt_chunk`` receives a ``chunk_index`` that
    was already decrypted on this session. Caller can map this to
    an ACK-reject with reason=``native_chunk_replay`` to keep the
    channel alive (matches T2-E / Batch P discipline)."""


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

    Constructed via :func:`establish_session_pair` or
    :func:`session_from_shared_secret`. Holds:

    - The session's shared secret (32 bytes from the hybrid KEM).
    - A :class:`ChunkRatchet` for per-chunk key derivation.
    - An AEAD primitive keyed off the session root + chunk_id AAD.
    - Optional :class:`ChunkStore` for persistent dedup + recall.

    Two cipher backends are available, selected by ``cipher_backend``:

    - ``"fast"`` (default): uses ``cryptography.hazmat`` ChaCha20-Poly1305
      / AES-GCM — wraps BoringSSL's hand-tuned assembly. Single-shot
      AEAD per chunk, chunk_id bound as AAD. ~2× faster than the
      native multi-frame path on small chunks; matches it on large.

    - ``"native"``: uses ``one_link_native.aead.AeadCipher`` — ADR-0002
      multi-frame layout with 16 KiB AEAD frames. Provides
      partial-chunk integrity (each frame independently verifiable),
      which the chunk-store transport doesn't currently use because
      chunks are received atomically. Kept available for future
      streaming-chunk scenarios.

    Sender and receiver instances bootstrapped from the SAME shared
    secret produce matching ratchet keys at matching indexes, so the
    receiver can decrypt without per-chunk key exchange.
    """

    shared_secret: bytes
    aead_kind: str  # "aes" or "chacha"
    store_root: Optional[Path] = None
    cipher_backend: str = "fast"  # "fast" | "native"

    # Internal state — set up in __post_init__. `Any` because the
    # pyo3 binding types are not statically importable on hosts that
    # don't have one_link_native installed (HAS_NATIVE=False path).
    _ratchet: Any = field(default=None, init=False, repr=False)
    _cipher: Any = field(default=None, init=False, repr=False)
    _store: Any = field(default=None, init=False, repr=False)
    _next_send_index: int = field(default=0, init=False)
    # Fast-path AEAD primitive (cryptography.hazmat) — None when using
    # the native multi-frame backend.
    _fast_aead: Any = field(default=None, init=False, repr=False)
    # 2026-05-22 audit Batch T: per-session replay window. T1-B added
    # per-chunk_index AEAD keys but the daemon's receive path still
    # accepted wire-supplied ``chunk_index`` without a replay window
    # or monotonicity gate. A sender (or relay) re-presenting an
    # already-decrypted (index, ciphertext) tuple wastes bandwidth +
    # confuses the per-file ``received`` accounting (which is bounded
    # at the daemon level by T2-E follow-up but still wastes a decrypt).
    # Track the SET of recently-decrypted indices and refuse a re-decrypt.
    # Bounded at 16 384 entries (≈ 4 GB of chunked content) with FIFO
    # eviction; the highest-water mark + window-size approach matches
    # the Double Ratchet's MAX_SKIP_KEYS pattern.
    _recent_decrypted_indices: Any = field(default=None, init=False, repr=False)

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
        if self.cipher_backend not in {"fast", "native"}:
            raise ValueError(
                f"cipher_backend must be 'fast' or 'native', got "
                f"{self.cipher_backend!r}"
            )
        from . import chunk_ratchet

        self._ratchet = chunk_ratchet.ChunkRatchet.from_shared_secret(
            self.shared_secret
        )
        # T1-B: skipped-key store, lazily created on first decrypt
        # to handle OOO chunk delivery (QUIC parallel lanes etc).
        self._skipped_store = None
        # Batch T: replay-window store. OrderedDict so eviction is
        # FIFO (oldest decrypted index drops first, matching ratchet
        # MAX_SKIP_KEYS semantics — adversary can't randomly purge an
        # honest index from the seen set).
        from collections import OrderedDict as _OD
        self._recent_decrypted_indices = _OD()
        if self.cipher_backend == "native":
            # Native multi-frame AEAD (ADR-0002). Used when partial-
            # chunk integrity is the priority.
            self._cipher = _native_aead.new_cipher(
                self.shared_secret, self.aead_kind
            )
        else:
            # Fast path: cryptography.hazmat (BoringSSL under the hood).
            # The single-shot AEAD is dramatically faster on small
            # chunks because it's one C call, not 16-KiB-frame
            # bookkeeping. Same security properties — chunk_id is
            # bound as AAD, so swaps/tampering still fail the tag.
            from cryptography.hazmat.primitives.ciphers.aead import (
                AESGCM,
                ChaCha20Poly1305,
            )

            if self.aead_kind == "aes":
                self._fast_aead = AESGCM(self.shared_secret)
            else:
                self._fast_aead = ChaCha20Poly1305(self.shared_secret)
        if self.store_root is not None:
            self._store = _native_store.open_store(str(self.store_root))

    # ── send side ───────────────────────────────────────────────────

    def encrypt_chunk_bytes(
        self,
        plaintext: bytes,
        *,
        chunk_id: Optional[bytes] = None,
        address_kind: str = "raw",
    ) -> NativeChunkRecord:
        """Encrypt one chunk. ``plaintext`` must be ≤256 KiB (the
        native AEAD layer's hard cap). If ``chunk_id`` is None we
        derive it from the chosen ``address_kind``:

        * ``"raw"`` (default): ``BLAKE3(plaintext)`` — per-recipient
          chunk IDs; identical plaintext from two senders produces
          different chunk IDs. The conservative choice.
        * ``"convergent"``: ``BLAKE3.derive_key("ol-chunk-addr-
          convergent-v1", plaintext)`` — opt-in for raw-media types
          whose plaintext bytes don't leak per-recipient information.
          Enables cross-sender dedup at the storage layer.

        Explicit ``chunk_id`` (already-computed) bypasses the
        derivation entirely. Performance: the AEAD layer's tag
        covers chunk_id as AAD, so we DON'T re-hash on receive —
        verification is via the AEAD tag itself, saving one full
        BLAKE3 pass per chunk on both sides.
        """
        if len(plaintext) > 256 * 1024:
            raise ValueError(
                f"chunk plaintext exceeds 256 KiB limit "
                f"({len(plaintext)} bytes); split via cdc_iter first"
            )
        if chunk_id is None:
            if address_kind == "convergent":
                chunk_id = _native_chunk.chunk_address_convergent(plaintext)
            else:
                chunk_id = _native_chunk.chunk_address_raw(plaintext)
        # The pyo3 binding already produces a bytes-like object; only
        # wrap when the upstream returned something non-bytes
        # (defensive — saves an allocation in the common path).
        if not isinstance(chunk_id, bytes):
            chunk_id = bytes(chunk_id)
        idx = self._next_send_index
        self._next_send_index += 1
        # 2026-05-21 audit T1-B: ratchet-keyed per-chunk AEAD when
        # the local + peer caps both advertise NATIVE_TRANSFER_INDEXED_V2.
        # Sender derives ``chunk_key`` from the per-chunk ratchet
        # step and uses it as the AEAD key (instead of session-static
        # ``self.shared_secret``). Receiver derives the same key via
        # ``ratchet.key_at(record.chunk_index)`` so OOO QUIC delivery
        # still decrypts. Within-channel forward secrecy: compromise
        # of chunk N's key reveals chunk N only — chunks 0..N-1 are
        # protected by the ratchet's irreversible one-way chain.
        # Cost: ~3.6% per-chunk slowdown vs the prior static-key path
        # (measured 77 µs vs 74 µs on 256 KiB; bench
        # ``native_aead T1-B candidate`` in
        # ``scripts/bench_audit_2026_05_21.py``).
        chunk_key, _ratchet_idx = self._ratchet.next_key()
        if self._fast_aead is not None:
            # Fast path: build a per-chunk AEAD using the ratchet
            # output. The 12-byte nonce is still the chunk index so
            # two chunks of the same plaintext still encrypt to
            # different ciphertexts (defense-in-depth; with a unique
            # per-chunk key the nonce is technically free, but
            # keeping a counter nonce is cheap and surfaces wire
            # bugs immediately if it ever collides).
            from cryptography.hazmat.primitives.ciphers.aead import (
                AESGCM,
                ChaCha20Poly1305,
            )
            if self.aead_kind == "aes":
                per_chunk_aead = AESGCM(chunk_key)
            else:
                per_chunk_aead = ChaCha20Poly1305(chunk_key)
            nonce = idx.to_bytes(12, "little")
            ciphertext = per_chunk_aead.encrypt(nonce, plaintext, chunk_id)
        else:
            ciphertext = self._cipher.encrypt_chunk(chunk_id, plaintext)
            if not isinstance(ciphertext, bytes):
                ciphertext = bytes(ciphertext)
        return NativeChunkRecord(
            chunk_id=chunk_id,
            chunk_index=idx,
            plaintext_len=len(plaintext),
            ciphertext=ciphertext,
        )

    # Single-chunk fast path: files at or under the AEAD chunk cap
    # skip both CDC scan and multi-chunk framing.
    SINGLE_CHUNK_FAST_PATH_MAX: int = 256 * 1024
    # Fixed-chunk size used when ``chunk_strategy="fixed"`` — matches
    # the legacy channel's FILE_CHUNK 256 KiB granularity so the
    # native pipeline's per-chunk framing overhead amortizes the
    # same way the legacy path does.
    FIXED_CHUNK_SIZE: int = 256 * 1024
    # Streaming threshold: files above this are read in
    # ``FIXED_CHUNK_SIZE``-aligned blocks instead of slurped to
    # memory all at once.
    STREAMING_THRESHOLD: int = 16 * 1024 * 1024

    def encrypt_file(
        self,
        path: Path,
        *,
        chunk_strategy: str = "fixed",
    ) -> Iterator[NativeChunkRecord]:
        """Stream a file through the pipeline; dispatches to the
        addressing-aware path that picks raw vs convergent BLAKE3
        based on the file extension. See `_resolve_address_kind`."""
        """Stream a file through the pipeline.

        ``chunk_strategy``:

        - ``"fixed"`` (default): 256 KiB fixed chunks. Matches the
          legacy channel's FILE_CHUNK granularity, so the native
          pipeline has the same number of chunks per file as
          legacy — closes the per-chunk-framing overhead gap that
          shows up in CDC mode on the 1+ MiB range. Content-
          addressed dedup still works at fixed boundaries.
        - ``"cdc"``: content-defined chunking via ``cdc_iter`` with
          ADR-0001 parameters (8/64/256 KiB). Better dedup on edited
          files; more chunks per byte; slower steady-state on random
          payloads (CDC variation produces sub-optimal chunk counts).

        Three code paths, chosen by file size:

        - **≤256 KiB**: single-chunk fast path. One BLAKE3 + one AEAD
          pass, regardless of ``chunk_strategy``.
        - **size ≤ STREAMING_THRESHOLD**: read entire file, then
          chunk per ``chunk_strategy``.
        - **size > STREAMING_THRESHOLD**: stream the file in
          ``FIXED_CHUNK_SIZE``-aligned blocks, encrypting each
          block on the fly. ``chunk_strategy="cdc"`` falls back to
          fixed boundaries in this mode (full-file CDC requires
          having the whole file in memory).
        """
        if chunk_strategy not in {"fixed", "cdc"}:
            raise ValueError(
                f"chunk_strategy must be 'fixed' or 'cdc', got "
                f"{chunk_strategy!r}"
            )
        path = Path(path)
        size = path.stat().st_size
        # Phase B convergent-encryption default: raw-media files get
        # convergent BLAKE3 addresses (enables cross-sender dedup);
        # everything else stays on raw-BLAKE3 (per-recipient keys).
        addr_kind = self._resolve_address_kind(path)

        if size <= self.SINGLE_CHUNK_FAST_PATH_MAX:
            plaintext = path.read_bytes()
            chunk_id = self._compute_address(plaintext, addr_kind)
            record = self.encrypt_chunk_bytes(plaintext, chunk_id=chunk_id)
            self._maybe_store(record, address_kind=addr_kind)
            yield record
            return

        if size <= self.STREAMING_THRESHOLD:
            data = path.read_bytes()
            yield from self._encrypt_buffer(data, chunk_strategy, addr_kind)
            return

        # 2026-05-22 audit Batch T: stop reading when ``size`` bytes
        # have been yielded, even if the underlying file has grown
        # mid-send. Without this cap, a growing source file produces
        # extra encrypted chunks past the declared size; the receiver
        # rejects them via the T2-E overrun-size guard but the
        # sender's ratchet has already advanced for those extra
        # chunks, desynchronising the next file on the channel.
        bytes_sent = 0
        with path.open("rb") as f:
            while bytes_sent < size:
                remaining = size - bytes_sent
                block = f.read(min(self.FIXED_CHUNK_SIZE, remaining))
                if not block:
                    break
                chunk_id = self._compute_address(block, addr_kind)
                record = self.encrypt_chunk_bytes(block, chunk_id=chunk_id)
                self._maybe_store(record, address_kind=addr_kind)
                bytes_sent += len(block)
                yield record

    # ── address-kind dispatch (Phase B convergent encryption) ──────

    @staticmethod
    def _resolve_address_kind(path: Path) -> str:
        """Return ``"convergent"`` for raw-media file extensions,
        ``"raw"`` otherwise. Mirrors
        :func:`ol_chunk_store::convergent_default_for_content_type`
        — the canonical Rust dispatch. Keeping both sides in sync is
        intentional; the Python helper is the daemon-facing
        decision-point, the Rust helper is the chunk-store-facing
        one."""
        ext = path.suffix.lstrip(".").lower()
        media_exts = {
            "mp4", "m4v", "mov", "3gp", "mkv", "webm", "avi",
            "mp3", "wav", "flac", "ogg", "opus", "aac", "m4a",
            "jpg", "jpeg", "png", "gif", "webp", "heic",
            "h264", "264", "avc",
        }
        return "convergent" if ext in media_exts else "raw"

    @staticmethod
    def _compute_address(plaintext: bytes, kind: str) -> bytes:
        """Compute the chunk_id for ``plaintext`` under the chosen
        addressing scheme."""
        if kind == "convergent":
            return _native_chunk.chunk_address_convergent(plaintext)
        return _native_chunk.chunk_address_raw(plaintext)

    def _encrypt_buffer(
        self,
        data: bytes,
        chunk_strategy: str,
        address_kind: str = "raw",
    ) -> Iterator[NativeChunkRecord]:
        """Chunk + encrypt an in-memory buffer per ``chunk_strategy``."""
        if chunk_strategy == "fixed":
            step = self.FIXED_CHUNK_SIZE
            for i in range(0, len(data), step):
                chunk = data[i : i + step]
                chunk_id = self._compute_address(chunk, address_kind)
                record = self.encrypt_chunk_bytes(chunk, chunk_id=chunk_id)
                self._maybe_store(record, address_kind=address_kind)
                yield record
        else:
            for boundary in _native_chunk.cdc_iter(data):
                chunk = data[boundary.start : boundary.end]
                # cdc_iter boundaries carry the raw address; for the
                # convergent case we recompute. The boundary's
                # raw_address is wasted work in the convergent path
                # but the CDC scan dominates so the extra hash is < 1%.
                chunk_id = (
                    boundary.raw_address
                    if address_kind == "raw"
                    else _native_chunk.chunk_address_convergent(chunk)
                )
                record = self.encrypt_chunk_bytes(chunk, chunk_id=chunk_id)
                self._maybe_store(record, address_kind=address_kind)
                yield record

    def _maybe_store(
        self,
        record: NativeChunkRecord,
        *,
        address_kind: str = "raw",
    ) -> None:
        """If a ChunkStore is attached, persist ``record``. Dedup is
        handled by the store's Bloom front."""
        if self._store is None:
            return
        if self._store.has_chunk(record.chunk_id):
            return
        try:
            self._store.append_chunk(
                record_kind="blob",
                address_kind=address_kind,
                aead_kind=self.aead_kind,
                chunk_id=record.chunk_id,
                ratchet_key_id=b"\x00" * 16,
                length_plaintext=record.plaintext_len,
                ciphertext=record.ciphertext,
            )
        except Exception as exc:
            # 2026-05-22 audit Batch W: chunk-store append failure
            # silently disabled swarm-pull for the next peer that
            # asked for this chunk (we'd have it on disk via the
            # outbound transfer but the store's index never learned).
            # Record on the session's _degradation_events so the
            # daemon's diagnostics surface can show "this peer's
            # chunk-store append is failing, swarm-dedupe degraded."
            log.warning("native chunk-store append failed (%s)", exc)
            if not hasattr(self, "_store_failures"):
                self._store_failures = []
            self._store_failures.append({
                "at_ms": int(time.time() * 1000),
                "chunk_id_prefix": record.chunk_id.hex()[:16],
                "reason": f"{type(exc).__name__}: {exc}"[:128],
            })
            # Bound the failure log so a totally broken store doesn't
            # OOM us through this list.
            if len(self._store_failures) > 256:
                self._store_failures = self._store_failures[-256:]

    # ── receive side ────────────────────────────────────────────────

    def decrypt_chunk(self, record: NativeChunkRecord) -> bytes:
        """Decrypt a chunk record produced by the matching sender.

        Integrity is guaranteed by the AEAD tag binding ``chunk_id``
        as AAD: any chunk_id mismatch fails the tag check inside the
        AEAD layer, raising before any plaintext is exposed.

        2026-05-21 audit T2-D: a paired-but-malicious peer could
        legally craft a chunk whose ``chunk_id`` matches some other
        blob's known hash and ship arbitrary plaintext encrypted
        under that AAD. AEAD verifies "sender committed to this
        chunk_id" but NOT "chunk_id == BLAKE3(plaintext)". With
        convergent addressing the local chunk_store could then be
        poisoned: another peer asking ``has_chunk(target_id)`` would
        be served the attacker's bytes from our cache.

        Defense: when ``ONE_LINK_VERIFY_CHUNK_HASH=1`` is set,
        after decrypt we recompute ``BLAKE3(plaintext)`` and verify
        ``== chunk_id`` before returning. Default off because
        BLAKE3 over a 256 KiB chunk is ~85 µs (~33% slowdown on
        the receive hot path). Operators in adversarial-peer
        environments flip the flag; everyone else trusts the AAD-
        as-commitment property + the peer's pinned trust.
        """
        # 2026-05-22 audit Batch T: replay-window check. Reject a
        # re-presented chunk_index BEFORE deriving keys + decrypting.
        # T1-B made the AEAD safe under index reuse (different keys),
        # but the daemon still wrote the duplicate payload to the
        # blob's append handle, wasting bandwidth + CPU + flagging
        # the file as size-overrun. With the seen-set short-circuit
        # the duplicate is bounced free.
        idx_key = int(record.chunk_index)
        if idx_key in self._recent_decrypted_indices:
            raise ReplayError(
                f"chunk_index {idx_key} already decrypted this session "
                f"(replay or duplicate delivery)"
            )
        # 2026-05-21 audit T1-B: derive the matching per-chunk key
        # via ``ratchet.key_at(chunk_index)``. Handles OOO QUIC
        # delivery via the skipped-key store (intermediate keys are
        # cached so a delayed chunk can still derive its key). The
        # lazy ``_skipped_store`` is per-session; size capped at
        # ``ChunkRatchet.skipped_store(cap=1024)``.
        if self._skipped_store is None:
            self._skipped_store = self._ratchet.skipped_store()
        chunk_key = self._ratchet.key_at(
            int(record.chunk_index), skipped=self._skipped_store,
        )
        if self._fast_aead is not None:
            from cryptography.hazmat.primitives.ciphers.aead import (
                AESGCM,
                ChaCha20Poly1305,
            )
            if self.aead_kind == "aes":
                per_chunk_aead = AESGCM(chunk_key)
            else:
                per_chunk_aead = ChaCha20Poly1305(chunk_key)
            nonce = record.chunk_index.to_bytes(12, "little")
            plaintext = per_chunk_aead.decrypt(
                nonce, record.ciphertext, record.chunk_id
            )
        else:
            plaintext = self._cipher.decrypt_chunk(
                record.chunk_id,
                record.plaintext_len,
                record.ciphertext,
            )
            if not isinstance(plaintext, bytes):
                plaintext = bytes(plaintext)
        # T2-D paranoid-mode hash re-verify.
        if _VERIFY_CHUNK_HASH:
            import blake3 as _blake3
            actual = _blake3.blake3(plaintext).digest()
            if actual != bytes(record.chunk_id):
                raise ValueError(
                    f"chunk_id mismatch on decrypt: declared "
                    f"{bytes(record.chunk_id).hex()[:16]}, actual "
                    f"{actual.hex()[:16]} (ONE_LINK_VERIFY_CHUNK_HASH=1)"
                )
        # Batch T: record this index as decrypted, FIFO-evicting the
        # oldest entry once the cap is hit.
        self._recent_decrypted_indices[idx_key] = None
        if len(self._recent_decrypted_indices) > _REPLAY_WINDOW_MAX:
            with __import__("contextlib").suppress(KeyError):
                self._recent_decrypted_indices.popitem(last=False)
        return plaintext

    def decrypt_records_to_bytes(
        self, records: list[NativeChunkRecord]
    ) -> bytes:
        """Convenience: decrypt and concatenate a list of records in
        order. Returns the assembled plaintext bytes."""
        # b"".join over a list is faster than over a generator because
        # join can preallocate the output buffer when it knows the
        # total length. For very large transfers, a memoryview-based
        # concatenation would be faster still; keep the simple form
        # because that's not the hot path (the hot path is per-chunk
        # transport delivery, not bulk reassembly).
        return b"".join(self.decrypt_chunk(r) for r in records)


# ─── Session establishment ─────────────────────────────────────────────────


def establish_session_pair(
    *,
    aead_kind: str = "chacha",
    sender_store_root: Optional[Path] = None,
    receiver_store_root: Optional[Path] = None,
    cipher_backend: str = "fast",
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
    # ES-18: explicit raise, not assert. KEM round-trip mismatch is a
    # crypto-correctness invariant — under python -O the assert would
    # disappear and we'd silently set up sessions with mismatched
    # shared secrets that fail later in AEAD with "invalid tag".
    if shared_send != shared_recv:
        raise RuntimeError("KEM round-trip failed: shared_send != shared_recv")

    sender = NativeTransferSession(
        shared_secret=shared_send,
        aead_kind=aead_kind,
        store_root=sender_store_root,
        cipher_backend=cipher_backend,
    )
    receiver = NativeTransferSession(
        shared_secret=shared_recv,
        aead_kind=aead_kind,
        store_root=receiver_store_root,
        cipher_backend=cipher_backend,
    )
    return sender, receiver


def session_from_shared_secret(
    shared_secret: bytes,
    *,
    aead_kind: Optional[str] = None,
    store_root: Optional[Path] = None,
    cipher_backend: str = "fast",
) -> NativeTransferSession:
    """Build a session from a pre-established 32-byte shared secret.
    Daemon callers wire in the channel handshake's
    ``HKDF(shared_secret, salt, info=...)`` output here.

    ``aead_kind`` defaults to AES on hosts with hardware AES-NI,
    ChaCha20-Poly1305 elsewhere — the same heuristic the legacy
    channel uses for its session cipher.

    ``cipher_backend`` defaults to ``"fast"`` (cryptography.hazmat
    BoringSSL-backed AEAD); set to ``"native"`` to use
    ``ol_aead.AeadCipher`` (ADR-0002 multi-frame layout)."""
    if not HAS_NATIVE:
        raise RuntimeError("native_transfer requires one_link_native")
    if aead_kind is None:
        aead_kind = "aes" if _native_aead.host_has_hardware_aes() else "chacha"
    return NativeTransferSession(
        shared_secret=shared_secret,
        aead_kind=aead_kind,
        store_root=store_root,
        cipher_backend=cipher_backend,
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
