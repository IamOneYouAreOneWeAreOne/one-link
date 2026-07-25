"""End-to-end native file-transfer pipeline (ADR-0025, Phase C-3 cutover).

Composes the file-engine v2 native primitives into a single Python
surface so the daemon (and tests) can drive a full send → receive flow
against the new stack:

  1. **Session establishment** via :func:`pq_hybrid.default_kem` — requires
     the verified native ML-KEM-768 + X25519 backend (ADR-0017) and fails
     closed by default.  Classical-only test/migration use is an explicit
     caller option and is never advertised as post-quantum.

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

import hmac
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger(__name__)

# Lazy native-module loading so the module imports cleanly on hosts
# without the wheel installed. Callers check `HAS_NATIVE` before
# touching any function that needs the native crates.
_native_aead: Any = None
_native_chunk: Any = None
_native_store: Any = None
_native_root: Any = None
try:
    import one_link_native
    from one_link_native import aead as _native_aead  # type: ignore[attr-defined,no-redef]
    from one_link_native import chunk as _native_chunk  # type: ignore[attr-defined,no-redef]
    from one_link_native import store as _native_store  # type: ignore[attr-defined,no-redef]

    _native_root = one_link_native
    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    log.info(
        "native_transfer requires one_link_native (%s); the pipeline is "
        "unavailable until the wheel is built via `cd native && "
        "maturin develop --release`.",
        exc,
    )

_STORE_OPERATION_ERRORS: tuple[type[BaseException], ...] = (OSError, ValueError)
if HAS_NATIVE:
    # ADR-0008 maps durable-store/WAL failures to this dedicated exception.
    # Keep TypeError/AttributeError out of the degradation boundary: those
    # indicate an API/programming defect and must stop the transfer loudly.
    _STORE_OPERATION_ERRORS += (_native_root.OlChunkStoreError,)


# Re-exported constants (kept in sync with the native crate via stubs).
CDC_AVG_SIZE: int = 64 * 1024  # 64 KiB — matches ADR-0001 default
AEAD_TAG_LEN: int = 16
AEAD_FRAME_PLAINTEXT_LEN: int = 16 * 1024  # 16 KiB per AEAD frame
SHARED_SECRET_LEN: int = 32
MAX_CHUNK_PLAINTEXT_LEN: int = 256 * 1024
MAX_CHUNK_CIPHERTEXT_LEN: int = MAX_CHUNK_PLAINTEXT_LEN + 4096
MAX_RATCHET_SKIP: int = 1024

# Native transfer is bidirectional over one authenticated Channel.  A single
# root used in both directions is unsafe: both senders start at chunk index
# zero, so simultaneous traffic repeats the same (key, nonce) pair.  Derive
# independent traffic roots with explicit protocol labels before constructing
# the per-direction ratchets.  The transcript is supplied as HKDF salt by the
# Channel integration, binding the traffic roots to that exact handshake.
_DIRECTION_SECRET_INFO_PREFIX = b"OL1/native-transfer/traffic-secret|v2|"
_INITIATOR_TO_RESPONDER = b"initiator-to-responder"
_RESPONDER_TO_INITIATOR = b"responder-to-initiator"

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
    _store_failures: list[dict[str, Any]] = field(
        default_factory=list,
        init=False,
        repr=False,
    )
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

        * ``"raw"`` (default): ``BLAKE3(plaintext)`` — ordinary global
          content addressing.
        * ``"convergent"``: ``BLAKE3.derive_key("ol-chunk-addr-
          convergent-v1", plaintext)`` — opt-in for raw-media types
          whose plaintext bytes don't leak per-recipient information.
          Enables cross-sender dedup at the storage layer.

        Explicit ``chunk_id`` (already-computed) bypasses sender-side
        derivation. The receiver still proves that it is either the raw or
        convergent address of the authenticated plaintext before returning it.
        """
        if len(plaintext) > MAX_CHUNK_PLAINTEXT_LEN:
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
                per_chunk_aead: AESGCM | ChaCha20Poly1305 = AESGCM(chunk_key)
            else:
                per_chunk_aead = ChaCha20Poly1305(chunk_key)
            nonce = idx.to_bytes(12, "little")
            ciphertext = per_chunk_aead.encrypt(nonce, plaintext, chunk_id)
        else:
            # The native multi-frame backend must use the ratchet output too;
            # a session-static cipher would silently discard the advertised
            # per-chunk forward secrecy.
            per_chunk_cipher = _native_aead.new_cipher(chunk_key, self.aead_kind)
            ciphertext = per_chunk_cipher.encrypt_chunk(chunk_id, plaintext)
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
        source_stat = path.stat()
        size = source_stat.st_size
        # Phase B convergent-encryption default: raw-media files get
        # convergent BLAKE3 addresses (enables cross-sender dedup);
        # everything else stays on raw-BLAKE3 (per-recipient keys).
        addr_kind = self._resolve_address_kind(path)

        if size <= self.SINGLE_CHUNK_FAST_PATH_MAX:
            plaintext = path.read_bytes()
            self._assert_source_stable(path, source_stat, len(plaintext))
            chunk_id = self._compute_address(plaintext, addr_kind)
            record = self.encrypt_chunk_bytes(plaintext, chunk_id=chunk_id)
            self._maybe_store(record, address_kind=addr_kind)
            yield record
            return

        if size <= self.STREAMING_THRESHOLD:
            data = path.read_bytes()
            self._assert_source_stable(path, source_stat, len(data))
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
        self._assert_source_stable(path, source_stat, bytes_sent)

    @staticmethod
    def _assert_source_stable(path: Path, before: Any, bytes_read: int) -> None:
        """Fail a transfer whose source changed during streaming.

        Silently reaching EOF after a source was truncated left the receiver
        waiting forever for the declared byte count. A same-path replacement
        could instead send bytes that no longer matched the offer. Both are
        recoverable retry conditions, but only if the sender reports them.
        """
        after = path.stat()
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if bytes_read != before.st_size or identity_after != identity_before:
            raise OSError(
                "native transfer source changed or was truncated while reading "
                f"{path} (declared={before.st_size}, read={bytes_read}, "
                f"current={after.st_size})"
            )

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
        try:
            if self._store.has_chunk(record.chunk_id):
                return
            self._store.append_chunk(
                record_kind="blob",
                address_kind=address_kind,
                aead_kind=self.aead_kind,
                chunk_id=record.chunk_id,
                ratchet_key_id=b"\x00" * 16,
                length_plaintext=record.plaintext_len,
                ciphertext=record.ciphertext,
            )
        except _STORE_OPERATION_ERRORS as exc:
            # 2026-05-22 audit Batch W: chunk-store lookup/append failure
            # silently disabled swarm-pull for the next peer that
            # asked for this chunk (we'd have it on disk via the
            # outbound transfer but the store's index never learned).
            # Record on the session's _degradation_events so the
            # daemon's diagnostics surface can show "this peer's
            # chunk-store append is failing, swarm-dedupe degraded."
            log.warning("native chunk-store operation failed (%s)", exc)
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

        The AEAD tag binds ``chunk_id`` as AAD, and a mandatory post-decrypt
        content-address check proves the authenticated ID is derived from the
        plaintext before a caller can persist it.

        2026-05-21 audit T2-D: a paired-but-malicious peer could
        legally craft a chunk whose ``chunk_id`` matches some other
        blob's known hash and ship arbitrary plaintext encrypted
        under that AAD. AEAD verifies "sender committed to this
        chunk_id" but NOT "chunk_id == BLAKE3(plaintext)". With
        convergent addressing the local chunk_store could then be
        poisoned: another peer asking ``has_chunk(target_id)`` would
        be served the attacker's bytes from our cache.

        Defense: after decrypt we always recompute the raw address, and only
        on mismatch compute the convergent address. The declared ID must match
        one of those protocol-defined content addresses. This is a production
        integrity boundary, not an operator-controlled speed knob.
        """
        # 2026-05-22 audit Batch T: replay-window check. Reject a
        # re-presented chunk_index BEFORE deriving keys + decrypting.
        # T1-B made the AEAD safe under index reuse (different keys),
        # but the daemon still wrote the duplicate payload to the
        # blob's append handle, wasting bandwidth + CPU + flagging
        # the file as size-overrun. With the seen-set short-circuit
        # the duplicate is bounced free.
        idx_key = int(record.chunk_index)
        if idx_key < 0:
            raise ValueError("chunk_index must be non-negative")
        current_index = int(self._ratchet.current_index)
        if idx_key > current_index + MAX_RATCHET_SKIP:
            raise ValueError(
                f"chunk_index {idx_key} exceeds receive window "
                f"({current_index}..{current_index + MAX_RATCHET_SKIP})"
            )
        if not 0 <= int(record.plaintext_len) <= MAX_CHUNK_PLAINTEXT_LEN:
            raise ValueError(
                f"plaintext_len out of range: {record.plaintext_len}"
            )
        if len(record.chunk_id) != 32:
            raise ValueError("chunk_id must be exactly 32 bytes")
        if not AEAD_TAG_LEN <= len(record.ciphertext) <= MAX_CHUNK_CIPHERTEXT_LEN:
            raise ValueError(
                f"ciphertext length out of range: {len(record.ciphertext)}"
            )
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
        in_order = idx_key == current_index
        if in_order:
            # Derive without committing the ratchet.  A forged tag must not
            # consume the honest next key and desynchronize every later file.
            chunk_key = self._ratchet.peek_at_current()
        else:
            chunk_key = self._ratchet.key_at(
                idx_key, skipped=self._skipped_store,
            )
        if self._fast_aead is not None:
            from cryptography.hazmat.primitives.ciphers.aead import (
                AESGCM,
                ChaCha20Poly1305,
            )
            if self.aead_kind == "aes":
                per_chunk_aead: AESGCM | ChaCha20Poly1305 = AESGCM(chunk_key)
            else:
                per_chunk_aead = ChaCha20Poly1305(chunk_key)
            nonce = record.chunk_index.to_bytes(12, "little")
            plaintext = per_chunk_aead.decrypt(
                nonce, record.ciphertext, record.chunk_id
            )
        else:
            per_chunk_cipher = _native_aead.new_cipher(chunk_key, self.aead_kind)
            plaintext = per_chunk_cipher.decrypt_chunk(
                record.chunk_id,
                record.plaintext_len,
                record.ciphertext,
            )
            if not isinstance(plaintext, bytes):
                plaintext = bytes(plaintext)
        # T2-D: AAD authenticates the sender's claim but cannot make the
        # claim a content address. Verify raw first (the common one-hash path);
        # convergent media chunks pay the second hash only when necessary.
        declared_id = bytes(record.chunk_id)
        raw_id = bytes(_native_chunk.chunk_address_raw(plaintext))
        address_valid = hmac.compare_digest(declared_id, raw_id)
        if not address_valid:
            convergent_id = bytes(
                _native_chunk.chunk_address_convergent(plaintext)
            )
            address_valid = hmac.compare_digest(declared_id, convergent_id)
        if not address_valid:
            raise ValueError(
                "chunk_id is not a content address of decrypted plaintext: "
                f"declared={declared_id.hex()[:16]}, raw={raw_id.hex()[:16]}"
            )
        if in_order:
            _committed_key, committed_index = self._ratchet.next_key()
            if committed_index != idx_key:
                raise RuntimeError("native chunk ratchet commit index mismatch")
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


# ─── Bidirectional channel integration ─────────────────────────────────────


def derive_directional_secrets(
    root_secret: bytes,
    *,
    transcript_hash: bytes,
) -> tuple[bytes, bytes]:
    """Derive canonical native-transfer traffic secrets.

    Returns ``(initiator_to_responder, responder_to_initiator)``.  Calling
    peers use the same canonical ordering and map it to local TX/RX according
    to their authenticated handshake role.  Distinct HKDF info labels make
    the two roots cryptographically independent; consequently chunk index
    zero in each direction has neither a repeated AEAD key nor a repeated
    key/nonce pair.

    ``transcript_hash`` must be the authenticated channel transcript.  It is
    deliberately required rather than optional so a caller cannot create
    traffic roots that are accidentally reusable across channel handshakes.
    """
    root = bytes(root_secret)
    transcript = bytes(transcript_hash)
    if len(root) != SHARED_SECRET_LEN:
        raise ValueError(
            f"root_secret must be {SHARED_SECRET_LEN} bytes, got {len(root)}"
        )
    if len(transcript) != 32:
        raise ValueError(
            f"transcript_hash must be 32 bytes, got {len(transcript)}"
        )

    def _derive(label: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=SHARED_SECRET_LEN,
            salt=transcript,
            info=_DIRECTION_SECRET_INFO_PREFIX + label,
        ).derive(root)

    initiator_to_responder = _derive(_INITIATOR_TO_RESPONDER)
    responder_to_initiator = _derive(_RESPONDER_TO_INITIATOR)
    if initiator_to_responder == responder_to_initiator:
        # This is computationally unreachable for HKDF barring a catastrophic
        # implementation failure.  Keep the invariant executable: silently
        # reusing a root here would recreate the nonce-collision vulnerability.
        raise RuntimeError("native directional traffic-secret collision")
    return initiator_to_responder, responder_to_initiator


@dataclass(frozen=True, slots=True)
class NativeTransferDuplexSession:
    """Direction-safe native transfer facade for one authenticated channel.

    ``NativeTransferSession`` owns a stateful chunk ratchet and therefore must
    never be shared by channel TX and RX.  This facade preserves the daemon's
    existing one-object API while routing every encrypt operation to
    ``tx_session`` and every decrypt operation to ``rx_session``.  The two
    sessions are seeded from independent, role-bound traffic secrets.
    """

    tx_session: NativeTransferSession
    rx_session: NativeTransferSession

    def __post_init__(self) -> None:
        if self.tx_session is self.rx_session:
            raise ValueError("native TX and RX sessions must be distinct")
        if self.tx_session.shared_secret == self.rx_session.shared_secret:
            raise ValueError("native TX and RX traffic secrets must be distinct")
        if self.tx_session.aead_kind != self.rx_session.aead_kind:
            raise ValueError("native TX and RX AEAD kinds must match")
        if self.tx_session.cipher_backend != self.rx_session.cipher_backend:
            raise ValueError("native TX and RX cipher backends must match")

    def encrypt_chunk_bytes(
        self,
        plaintext: bytes,
        *,
        chunk_id: Optional[bytes] = None,
        address_kind: str = "raw",
    ) -> NativeChunkRecord:
        return self.tx_session.encrypt_chunk_bytes(
            plaintext,
            chunk_id=chunk_id,
            address_kind=address_kind,
        )

    def encrypt_file(
        self,
        path: Path,
        *,
        chunk_strategy: str = "fixed",
    ) -> Iterator[NativeChunkRecord]:
        return self.tx_session.encrypt_file(path, chunk_strategy=chunk_strategy)

    def decrypt_chunk(self, record: NativeChunkRecord) -> bytes:
        return self.rx_session.decrypt_chunk(record)

    def decrypt_records_to_bytes(
        self,
        records: list[NativeChunkRecord],
    ) -> bytes:
        return self.rx_session.decrypt_records_to_bytes(records)


def duplex_session_from_directional_secrets(
    tx_secret: bytes,
    rx_secret: bytes,
    *,
    aead_kind: Optional[str] = None,
    store_root: Optional[Path] = None,
    cipher_backend: str = "fast",
) -> NativeTransferDuplexSession:
    """Construct a direction-safe facade from role-mapped traffic roots."""
    tx = bytes(tx_secret)
    rx = bytes(rx_secret)
    if tx == rx:
        raise ValueError("native TX and RX traffic secrets must be distinct")
    return NativeTransferDuplexSession(
        tx_session=session_from_shared_secret(
            tx,
            aead_kind=aead_kind,
            store_root=store_root,
            cipher_backend=cipher_backend,
        ),
        rx_session=session_from_shared_secret(
            rx,
            aead_kind=aead_kind,
            # decrypt_chunk does not touch the outbound ciphertext store.
            # Opening the same native store twice can create avoidable lock
            # contention, so the one local TX session owns that handle.
            store_root=None,
            cipher_backend=cipher_backend,
        ),
    )


# ─── Session establishment ─────────────────────────────────────────────────


def establish_session_pair(
    *,
    aead_kind: str = "chacha",
    sender_store_root: Optional[Path] = None,
    receiver_store_root: Optional[Path] = None,
    cipher_backend: str = "fast",
    allow_classical_downgrade: bool = False,
) -> tuple[NativeTransferSession, NativeTransferSession]:
    """Fresh-keypair session establishment for in-process testing.

    Spins up a hybrid KEM, derives a 32-byte shared secret via
    ``default_kem().encapsulate(pk)``, and constructs paired
    sender + receiver sessions. Used by the round-trip tests; the daemon's
    real flow plugs in the confirmed channel-handshake secret via
    :func:`session_from_shared_secret`.  Classical-only construction requires
    an explicit ``allow_classical_downgrade=True`` argument.
    """
    from . import pq_hybrid

    kem = pq_hybrid.default_kem(
        allow_classical_downgrade=allow_classical_downgrade,
    )
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

    ``aead_kind`` defaults to ChaCha20-Poly1305 as a protocol constant.
    Cipher choice cannot depend on each endpoint's local CPU features: a
    heterogeneous AES-NI/non-AES pair must construct the same AEAD.

    ``cipher_backend`` defaults to ``"fast"`` (cryptography.hazmat
    BoringSSL-backed AEAD); set to ``"native"`` to use
    ``ol_aead.AeadCipher`` (ADR-0002 multi-frame layout)."""
    if not HAS_NATIVE:
        raise RuntimeError("native_transfer requires one_link_native")
    if aead_kind is None:
        aead_kind = "chacha"
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
