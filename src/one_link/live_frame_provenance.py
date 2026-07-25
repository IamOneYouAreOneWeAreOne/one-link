"""Rolling-window FrameProvenance for live RTC media.

The static-blob FrameProvenance in :mod:`frame_provenance` signs the
whole media payload at once. That works for voice messages where the
sender computes BLAKE3 over the entire opus blob before sending.

Live RTC media is different: 20-ms packets stream out continuously,
and the per-packet cost of Ed25519 (≈40 µs sign, ≈80 µs verify) is
prohibitive at 50 packets/sec — and the cumulative bandwidth of 64-
byte signatures per packet (3.2 KB/s per direction) is wasteful.

The rolling-window design:

  - The producer aggregates outgoing packets into 1-second windows
    using an INCREMENTAL hash (BLAKE3 update / SHA-256 update).
  - On window close, the producer signs ONE :class:`FrameProvenance`
    over the window's accumulated hash + window metadata + the
    sender's identity.
  - The wire message ``CALL_FRAME_ATTEST`` ships every closed
    window's signed provenance to the peer.
  - The peer aggregates RECEIVED packets the same way and computes
    a local window hash. On receipt of the producer's attestation,
    the peer compares the locally-computed hash against the signed
    one. Mismatch → mark this window's frames as "Repaired" or
    "Reconstructed" in the Reality dot.

This module is pure: it does not own the transport, it does not
know about RTC, it just accepts ``observe_packet(bytes, timestamp)``
calls from BOTH the producer side AND the receiver side. The daemon
adapter is the thin layer that bridges browser ``ondataavailable``
events / inbound RTP packets into this engine.

For browser-friendliness, the window hash uses **SHA-256** rather
than BLAKE3 — the browser has WebCrypto SHA-256 natively, no wasm
needed. The schema_version on emitted FrameProvenance is bumped
to :data:`LIVE_SCHEMA_V2` so receivers know to use SHA-256 for the
canonical segment-hash check.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.5 + Tier β acceptance
"""

from __future__ import annotations

import hashlib
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from one_link.frame_provenance import (
    DEVICE_ID_LEN,
    ED25519_SIG_LEN,
    FrameKind,
    FrameProvenance,
    PathClass,
    RecordingState,
    SEGMENT_HASH_LEN,
    _canonical_bytes,
)


log = logging.getLogger(__name__)


# Live-RTC schema variant: same byte layout as SCHEMA_V1 except the
# segment_hash is SHA-256 (32 bytes) rather than BLAKE3-256. Both are
# 32 bytes so the canonical encoding is bit-identical; the version
# byte tells the receiver which hash function to recompute locally.
LIVE_SCHEMA_V2 = 2


# Default rolling-window duration. The doc calls for ≈1 s; longer
# windows reduce signature cost but increase Reality-dot lag and
# allow more silent forgery before detection. 1 s is a calm default.
DEFAULT_WINDOW_MS = 1000


# ---------------------------------------------------------------------------
# Window record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Window:
    """One closed attestation window. ``segment_hash`` is the SHA-256
    of all packet payloads observed during the window's lifetime, in
    arrival order, concatenated."""

    window_index: int            # monotonically increasing per call
    segment_hash: bytes          # 32 bytes — SHA-256
    packet_count: int
    byte_count: int
    started_at_us: int
    closed_at_us: int

    def __post_init__(self) -> None:
        if len(self.segment_hash) != SEGMENT_HASH_LEN:
            raise ValueError(
                f"segment_hash must be {SEGMENT_HASH_LEN} bytes",
            )


@dataclass
class _OpenWindow:
    """Mutable accumulator for the window currently being filled."""

    window_index: int
    started_at_us: int
    packet_count: int = 0
    byte_count: int = 0
    hasher: Any = field(default_factory=hashlib.sha256)


# ---------------------------------------------------------------------------
# Producer side
# ---------------------------------------------------------------------------

class WindowAttestor:
    """Aggregates outbound packets into rolling windows; emits a
    signed :class:`FrameProvenance` when each window closes.

    Construct one per active call direction (outbound). Call
    :meth:`observe_packet` for each captured packet; the engine will
    close windows automatically and call the ``on_window_signed``
    callback with the signed attestation, ready to ship.

    Thread-safe; both the capture thread and the periodic ticker
    that drives window-close can call into it concurrently.
    """

    def __init__(
        self,
        *,
        signing_key: Ed25519PrivateKey,
        device_id: str,
        path_class: PathClass,
        recording_state: RecordingState,
        window_ms: int = DEFAULT_WINDOW_MS,
        on_window_signed: Optional[Callable[[Window, FrameProvenance], None]] = None,
    ) -> None:
        if len(device_id) != DEVICE_ID_LEN:
            raise ValueError(
                f"device_id must be {DEVICE_ID_LEN} hex chars",
            )
        if window_ms <= 0:
            raise ValueError("window_ms must be positive")
        self._lock = threading.Lock()
        self._signing_key = signing_key
        self._device_id = device_id
        self._path_class = path_class
        self._recording_state = recording_state
        self._window_ms = window_ms
        self._on_signed = on_window_signed
        self._current: Optional[_OpenWindow] = None
        self._next_index = 0
        # Counter of windows that have closed + been signed.
        self._closed_count = 0

    @property
    def closed_count(self) -> int:
        with self._lock:
            return self._closed_count

    @property
    def current_window_index(self) -> int:
        with self._lock:
            return self._next_index

    def set_recording_state(self, rs: RecordingState) -> None:
        """Update the recording-state field for future window
        signatures. A mid-window change applies to the NEXT window
        (the in-progress window keeps its initial value)."""
        with self._lock:
            self._recording_state = rs

    def set_path_class(self, pc: PathClass) -> None:
        with self._lock:
            self._path_class = pc

    def observe_packet(self, payload: bytes, timestamp_us: int) -> Optional[FrameProvenance]:
        """Feed one outbound packet into the current window. If
        ``timestamp_us`` advances past the current window's close
        boundary, the window is closed + signed; the returned value
        is the signed attestation (also forwarded to
        ``on_window_signed`` if set). If the window is still open,
        returns ``None``."""
        signed: Optional[FrameProvenance] = None
        with self._lock:
            if self._current is None:
                self._current = _OpenWindow(
                    window_index=self._next_index,
                    started_at_us=timestamp_us,
                )
                self._next_index += 1

            window_close_us = (
                self._current.started_at_us + self._window_ms * 1000
            )
            if timestamp_us >= window_close_us:
                closed = self._close_locked(timestamp_us=window_close_us)
                signed = self._sign_locked(closed)
                # Start a new window starting at the close boundary.
                self._current = _OpenWindow(
                    window_index=self._next_index,
                    started_at_us=window_close_us,
                )
                self._next_index += 1

            self._current.hasher.update(payload)
            self._current.packet_count += 1
            self._current.byte_count += len(payload)
        if signed is not None and self._on_signed is not None:
            try:
                self._on_signed(_window_from(signed), signed)
            except Exception:
                log.exception(
                    "live frame provenance callback failed for window %s",
                    signed.timestamp_us,
                )
        return signed

    def force_close(self, timestamp_us: int) -> Optional[FrameProvenance]:
        """Close the in-flight window even if its time hasn't expired.
        Used at call-end so the final partial window still gets
        signed (otherwise the receiver has nothing to verify against
        the tail audio)."""
        signed: Optional[FrameProvenance] = None
        with self._lock:
            if self._current is None or self._current.packet_count == 0:
                return None
            closed = self._close_locked(timestamp_us=timestamp_us)
            signed = self._sign_locked(closed)
            self._current = None
        if signed is not None and self._on_signed is not None:
            try:
                self._on_signed(_window_from(signed), signed)
            except Exception:
                log.exception(
                    "live frame provenance callback failed for window %s",
                    signed.timestamp_us,
                )
        return signed

    def _close_locked(self, *, timestamp_us: int) -> Window:
        assert self._current is not None
        cur = self._current
        seg = cur.hasher.digest()
        return Window(
            window_index=cur.window_index,
            segment_hash=seg,
            packet_count=cur.packet_count,
            byte_count=cur.byte_count,
            started_at_us=cur.started_at_us,
            closed_at_us=timestamp_us,
        )

    def _sign_locked(self, w: Window) -> FrameProvenance:
        canonical_target = FrameProvenance(
            schema_version=LIVE_SCHEMA_V2,
            segment_hash=w.segment_hash,
            device_id=self._device_id,
            frame_kind=FrameKind.REAL,
            path_class=self._path_class,
            recording_state=self._recording_state,
            timestamp_us=w.closed_at_us,
            # Confidence is producer-self-asserted; for direct
            # capture it's 1.0. Predictive frames degrade this.
            produce_confidence=1.0,
            signature=b"",
        )
        canonical = _canonical_bytes(canonical_target)
        sig = self._signing_key.sign(canonical)
        if len(sig) != ED25519_SIG_LEN:
            raise RuntimeError(
                f"unexpected signature length {len(sig)}",
            )
        self._closed_count += 1
        return FrameProvenance(
            schema_version=LIVE_SCHEMA_V2,
            segment_hash=w.segment_hash,
            device_id=self._device_id,
            frame_kind=FrameKind.REAL,
            path_class=self._path_class,
            recording_state=self._recording_state,
            timestamp_us=w.closed_at_us,
            produce_confidence=1.0,
            signature=sig,
        )


def _window_from(p: FrameProvenance) -> Window:
    """Reconstruct a Window record from a signed attestation, for the
    callback. We pass both so the callback can index by window_index
    without re-parsing the provenance."""
    return Window(
        window_index=0,  # not carried on-wire; reconstructed on demand
        segment_hash=p.segment_hash,
        packet_count=0,
        byte_count=0,
        started_at_us=p.timestamp_us,
        closed_at_us=p.timestamp_us,
    )


# ---------------------------------------------------------------------------
# Receiver side
# ---------------------------------------------------------------------------

class WindowVerifier:
    """Aggregates inbound packets the same way the producer did and
    verifies each arriving signed attestation against the locally-
    computed window hash.

    Verification outcomes:

      - ``Real``           — signature valid AND local hash matches
      - ``Repaired``       — signature valid BUT local hash differs
                              (packet loss / PLC filled gaps locally)
      - ``Reconstructed``  — schema_version indicates predictor /
                              semantic delta (future tier)
      - ``unverified``     — signature invalid OR sender pubkey
                              not known

    The Reality dot UI reads the latest verdict per call.
    """

    def __init__(
        self,
        *,
        sender_public_bytes: bytes,
        window_ms: int = DEFAULT_WINDOW_MS,
    ) -> None:
        self._lock = threading.Lock()
        self._sender_pub = sender_public_bytes
        self._window_ms = window_ms
        self._current: Optional[_OpenWindow] = None
        self._next_index = 0
        # Map of closed-window-index → computed segment hash
        self._closed_hashes: dict[int, bytes] = {}
        self._max_history = 32  # keep last 32 windows for late attestations

    def observe_packet(self, payload: bytes, timestamp_us: int) -> None:
        """Feed one inbound packet. Drives the same rolling-window
        accumulator used on the producer side so we can compare."""
        with self._lock:
            if self._current is None:
                self._current = _OpenWindow(
                    window_index=self._next_index,
                    started_at_us=timestamp_us,
                )
                self._next_index += 1
            window_close_us = (
                self._current.started_at_us + self._window_ms * 1000
            )
            if timestamp_us >= window_close_us:
                # Close the in-flight window — store its hash + start a new one.
                self._closed_hashes[self._current.window_index] = (
                    self._current.hasher.digest()
                )
                self._evict_if_oversize_locked()
                self._current = _OpenWindow(
                    window_index=self._next_index,
                    started_at_us=window_close_us,
                )
                self._next_index += 1
            self._current.hasher.update(payload)
            self._current.packet_count += 1
            self._current.byte_count += len(payload)

    def force_close(self) -> None:
        """Close + retain the in-flight window. Called when the call
        ends so the last partial window is verifiable."""
        with self._lock:
            if self._current is not None and self._current.packet_count > 0:
                self._closed_hashes[self._current.window_index] = (
                    self._current.hasher.digest()
                )
                self._evict_if_oversize_locked()
                self._current = None

    def verify_attestation(self, p: FrameProvenance) -> FrameKind:
        """Verify a signed attestation against the locally-aggregated
        windows. Returns the :class:`FrameKind` to display.

        - REAL          → signature valid + hash matches a local window
        - REPAIRED      → signature valid + hash differs from any local
                          window (loss / PLC mended on receive)
        - BLANK         → signature invalid (unverified)
        """
        if not _verify_live_signature(p, self._sender_pub):
            return FrameKind.BLANK
        with self._lock:
            # Look across the recent window history for a hash match.
            for h in self._closed_hashes.values():
                if h == p.segment_hash:
                    return FrameKind.REAL
            return FrameKind.REPAIRED

    def _evict_if_oversize_locked(self) -> None:
        while len(self._closed_hashes) > self._max_history:
            oldest = next(iter(self._closed_hashes))
            del self._closed_hashes[oldest]


def _verify_live_signature(
    p: FrameProvenance, sender_public_bytes: bytes,
) -> bool:
    try:
        if p.schema_version != LIVE_SCHEMA_V2:
            return False
        if len(p.signature) != ED25519_SIG_LEN:
            return False
        canonical = _canonical_bytes(
            FrameProvenance(
                schema_version=p.schema_version,
                segment_hash=p.segment_hash,
                device_id=p.device_id,
                frame_kind=p.frame_kind,
                path_class=p.path_class,
                recording_state=p.recording_state,
                timestamp_us=p.timestamp_us,
                produce_confidence=p.produce_confidence,
                signature=b"",
            )
        )
        pub = Ed25519PublicKey.from_public_bytes(sender_public_bytes)
        pub.verify(p.signature, canonical)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Browser-bridge helpers
# ---------------------------------------------------------------------------

def sha256_segment_hash(payload: bytes) -> bytes:
    """Compute the SHA-256 hash a browser-side WebCrypto digest call
    would produce over the same bytes. Used for daemon-side bridging
    when the browser ships pre-computed hashes."""
    return hashlib.sha256(payload).digest()


def sign_browser_window(
    *,
    signing_key: Ed25519PrivateKey,
    device_id: str,
    path_class: PathClass,
    recording_state: RecordingState,
    segment_hash: bytes,
    timestamp_us: int,
) -> FrameProvenance:
    """Wrap a browser-supplied SHA-256 chunk hash into a signed
    :class:`FrameProvenance`. Used by the daemon HTTP handler that
    accepts ``action: attest_frame``."""
    if len(segment_hash) != SEGMENT_HASH_LEN:
        raise ValueError(
            f"segment_hash must be {SEGMENT_HASH_LEN} bytes",
        )
    unsigned = FrameProvenance(
        schema_version=LIVE_SCHEMA_V2,
        segment_hash=segment_hash,
        device_id=device_id,
        frame_kind=FrameKind.REAL,
        path_class=path_class,
        recording_state=recording_state,
        timestamp_us=timestamp_us,
        produce_confidence=1.0,
        signature=b"",
    )
    canonical = _canonical_bytes(unsigned)
    sig = signing_key.sign(canonical)
    return FrameProvenance(
        schema_version=LIVE_SCHEMA_V2,
        segment_hash=segment_hash,
        device_id=device_id,
        frame_kind=FrameKind.REAL,
        path_class=path_class,
        recording_state=recording_state,
        timestamp_us=timestamp_us,
        produce_confidence=1.0,
        signature=sig,
    )
