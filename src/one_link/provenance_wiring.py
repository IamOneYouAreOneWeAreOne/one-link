"""Wire-format glue between FrameProvenance and the daemon.

The :mod:`frame_provenance` module is pure cryptography. This module
is the surgical adapter that:

  - Constructs the ``FILE_PROVENANCE`` wire message a sender emits
    after each ``FILE_OFFER`` (Tier α-pre target: voice messages
    v0.9.2 are the first surface to carry provenance, but any file
    transfer benefits identically — voice files are not specially
    cased).

  - Parses + verifies an inbound ``FILE_PROVENANCE`` message against
    the peer's pinned master public key.

  - Holds the per-blob provenance state in :class:`ProvenanceStore`
    so the HTTP layer can surface ``to_ui_dict(...)`` over the
    ``/api/events`` WebSocket when the UI renders a Reality dot.

The daemon imports exactly four symbols:

    make_send_provenance_msg(...)
    parse_inbound_provenance_msg(...)
    ProvenanceStore
    PROVENANCE_MSG_TYPE  ("FILE_PROVENANCE")

This keeps the wiring auditable in one file and the daemon's dispatch
table unmodified except for a single ``elif t == PROVENANCE_MSG_TYPE``
clause and a single emit-after-FILE_OFFER hook.

Compatibility:
  - Capability gate: a peer advertising ``FRAME_PROVENANCE_V1`` will
    receive provenance after every FILE_OFFER. Older peers ignore
    the unknown wire type (graceful degradation per wire.py:18).
  - Schema: wire dict uses the same field-name compaction defined in
    :func:`frame_provenance.to_wire_dict`.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any, Optional

from one_link.frame_provenance import (
    FrameKind,
    FrameProvenance,
    PathClass,
    RecordingState,
    from_wire_dict,
    make_segment_hash,
    now_us,
    sign_provenance,
    to_ui_dict,
    to_wire_dict,
    verify_provenance,
)
from one_link.identity import Identity

log = logging.getLogger(__name__)


# Wire message type. Added to the daemon dispatch switch in
# daemon._on_peer_message as a single elif clause.
PROVENANCE_MSG_TYPE = "FILE_PROVENANCE"

# Capability advertised by peers that support frame provenance. The
# sender only attaches a provenance message if BOTH peers advertise
# this — older peers ignore the unknown wire type, but we avoid the
# extra round-trip when we know the receiver can't act on it.
FRAME_PROVENANCE_CAP = "frame_provenance_v1"


# ---------------------------------------------------------------------------
# Send-side helpers
# ---------------------------------------------------------------------------

def build_provenance_for_file(
    *,
    identity: Identity,
    file_bytes: bytes,
    path_class: PathClass = PathClass.LAN,
    recording_state: RecordingState = RecordingState.NOT_RECORDING,
    frame_kind: FrameKind = FrameKind.REAL,
    produce_confidence: float = 1.0,
) -> FrameProvenance:
    """Sign a provenance tag for one outbound file.

    For Tier α-pre, voice messages v0.9.2 are the first surface; the
    "segment" is the full opus blob and ``frame_kind`` uses the legacy
    ``REAL`` wire value to mean sender-declared original input.  The
    signature binds bytes and declaration; it is not physical-sensor
    attestation. Future tiers may produce REPAIRED or
    RECONSTRUCTED files from PLC / semantic deltas; those cases
    set ``frame_kind`` accordingly.

    The ``path_class`` parameter reflects the network path the daemon
    chose for the *outbound* leg. The daemon knows this from its
    Route Brain state (Tier ε+); pre-α it defaults to LAN.
    """
    return build_provenance_for_hash(
        identity=identity,
        segment_hash=make_segment_hash(file_bytes),
        path_class=path_class,
        recording_state=recording_state,
        frame_kind=frame_kind,
        produce_confidence=produce_confidence,
    )


def build_provenance_for_hash(
    *,
    identity: Identity,
    segment_hash: bytes,
    path_class: PathClass = PathClass.LAN,
    recording_state: RecordingState = RecordingState.NOT_RECORDING,
    frame_kind: FrameKind = FrameKind.REAL,
    produce_confidence: float = 1.0,
) -> FrameProvenance:
    """Sign an already-computed canonical BLAKE3 content digest.

    Live file transfer computes the whole-file BLAKE3 while building its
    descriptor-bound manifest.  Reusing those exact 32 bytes avoids a second
    full-file read solely to attach provenance and guarantees the attestation
    and ``FILE_OFFER.blob`` identify the same content.
    """

    if not isinstance(segment_hash, bytes) or len(segment_hash) != 32:
        raise ValueError("segment_hash must be a 32-byte BLAKE3 digest")
    return sign_provenance(
        segment_hash=segment_hash,
        device_id=identity.short_id,
        frame_kind=frame_kind,
        path_class=path_class,
        recording_state=recording_state,
        timestamp_us=now_us(),
        produce_confidence=produce_confidence,
        signing_key=identity.private,
    )


def make_send_provenance_msg(
    *,
    sender_short_id: str,
    blob_hex: str,
    provenance: FrameProvenance,
) -> dict[str, Any]:
    """Wrap a FrameProvenance into the on-wire JSON envelope the
    daemon emits via ``channel.send(encode_msg(msg))``.

    ``blob_hex`` is the file's canonical BLAKE3-256 from ``FILE_OFFER``.
    It associates the provenance tag with a specific transfer and must
    exactly equal the signed ``segment_hash``.
    """
    if provenance.segment_hash.hex() != blob_hex:
        raise ValueError("provenance segment hash must match FILE_OFFER blob")
    from one_link.wire import make_msg

    return make_msg(
        PROVENANCE_MSG_TYPE,
        sender_short_id,
        blob=blob_hex,
        prov=to_wire_dict(provenance),
    )


# ---------------------------------------------------------------------------
# Receive-side helpers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParsedInbound:
    """Result of parsing a FILE_PROVENANCE wire message.

    ``provenance`` is the dataclass form; ``blob_hex`` is the file's
    canonical BLAKE3-256 that the FILE_OFFER / FILE_CHUNK pipeline uses for
    lookup.
    """

    blob_hex: str
    provenance: FrameProvenance


def parse_inbound_provenance_msg(msg: dict[str, Any]) -> ParsedInbound:
    """Parse and validate the on-wire envelope.

    Raises ``ValueError`` on malformed structure. Does NOT verify the
    cryptographic signature — that's the next step, done with the
    sender's pinned master public key via :func:`verify_inbound`.
    """
    if msg.get("t") != PROVENANCE_MSG_TYPE:
        raise ValueError(
            f"not a {PROVENANCE_MSG_TYPE} message: t={msg.get('t')!r}"
        )
    blob_hex = msg.get("blob")
    if not isinstance(blob_hex, str) or not blob_hex:
        raise ValueError(f"missing or invalid blob hex in {PROVENANCE_MSG_TYPE}")
    if len(blob_hex) != 64 or not all(c in "0123456789abcdef" for c in blob_hex.lower()):
        # BLAKE3-256 hex is 64 lowercase chars. Reject anything else so a
        # malicious peer can't shove arbitrary strings into the
        # provenance store key space.
        raise ValueError(f"blob hex malformed: {blob_hex!r}")
    prov_dict = msg.get("prov")
    if not isinstance(prov_dict, dict):
        raise ValueError(f"missing prov dict in {PROVENANCE_MSG_TYPE}")
    provenance = from_wire_dict(prov_dict)
    if provenance.segment_hash.hex() != blob_hex.lower():
        raise ValueError("provenance segment hash does not match offered blob")
    return ParsedInbound(blob_hex=blob_hex.lower(), provenance=provenance)


def verify_inbound(
    parsed: ParsedInbound,
    sender_public_bytes: bytes,
) -> bool:
    """Verify the inbound provenance against the sender's pinned master
    public key. Returns True/False; never raises."""
    return verify_provenance(parsed.provenance, sender_public_bytes)


# ---------------------------------------------------------------------------
# Persistent state — per-blob provenance for UI lookup
# ---------------------------------------------------------------------------

@dataclass
class _Entry:
    provenance: FrameProvenance
    verified: bool
    peer_fp: str
    recorded_at_us: int


class ProvenanceStore:
    """Thread-safe in-memory map of blob_hex → (provenance, verified).

    Lives on the Daemon instance and survives only that process.  Callers and
    product truth surfaces must not describe the indicator as durable across
    restart until this state is transactionally persisted alongside history.

    Used by:
      - the FILE_PROVENANCE inbound handler in daemon.py
      - the HTTP/WS layer to render the Reality dot
      - tests + the soak harness

    Memory bound: a small cap (default 4096 entries) is enforced so a
    peer cannot exhaust receiver memory by spamming provenance frames
    for files that were never offered. When the cap is hit, the
    oldest entry is evicted (FIFO via insertion order).
    """

    def __init__(self, max_entries: int = 4096) -> None:
        self._max = int(max_entries)
        # dict preserves insertion order on CPython 3.7+; we exploit
        # that for FIFO eviction without an OrderedDict import.
        self._inbound: dict[str, _Entry] = {}
        self._outbound: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    # -- inbound (something a peer sent us) --

    def record_inbound(
        self,
        *,
        blob_hex: str,
        peer_fp: str,
        provenance: FrameProvenance,
        verified: bool,
    ) -> None:
        with self._lock:
            self._inbound[blob_hex] = _Entry(
                provenance=provenance,
                verified=verified,
                peer_fp=peer_fp,
                recorded_at_us=now_us(),
            )
            self._evict_if_oversize(self._inbound)

    def get_inbound(self, blob_hex: str) -> Optional[_Entry]:
        with self._lock:
            return self._inbound.get(blob_hex)

    # -- outbound (something we sent) --

    def record_outbound(
        self,
        *,
        blob_hex: str,
        peer_fp: str,
        provenance: FrameProvenance,
    ) -> None:
        with self._lock:
            self._outbound[blob_hex] = _Entry(
                provenance=provenance,
                verified=True,  # we signed it; it's trivially verified
                peer_fp=peer_fp,
                recorded_at_us=now_us(),
            )
            self._evict_if_oversize(self._outbound)

    def get_outbound(self, blob_hex: str) -> Optional[_Entry]:
        with self._lock:
            return self._outbound.get(blob_hex)

    # -- UI lookup --

    def ui_state_for_blob(self, blob_hex: str) -> Optional[dict[str, Any]]:
        """Return the plain-language UI dict for a blob, or None.

        Looks inbound first (since the Reality dot is most often
        rendered on received messages), then outbound. Doctrine
        §3.9.a + §4.c — no hex / signatures in this dict.
        """
        with self._lock:
            entry = self._inbound.get(blob_hex) or self._outbound.get(blob_hex)
        if entry is None:
            return None
        return to_ui_dict(entry.provenance, verified=entry.verified)

    # -- maintenance --

    def _evict_if_oversize(self, target: dict[str, _Entry]) -> None:
        while len(target) > self._max:
            # FIFO eviction — drop the oldest key.
            oldest = next(iter(target))
            del target[oldest]

    def clear(self) -> None:
        with self._lock:
            self._inbound.clear()
            self._outbound.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._inbound) + len(self._outbound)


# ---------------------------------------------------------------------------
# Convenience: full round-trip flow (used by tests + by the daemon hook)
# ---------------------------------------------------------------------------

def handle_inbound_provenance(
    *,
    msg: dict[str, Any],
    peer_fp: str,
    sender_public_bytes: bytes,
    store: ProvenanceStore,
) -> tuple[Optional[ParsedInbound], bool]:
    """End-to-end inbound handler: parse, verify, record. Returns
    ``(parsed, verified)``; ``parsed`` is None if the message was
    malformed and was dropped.

    The daemon calls this from its single dispatch clause:

        elif t == PROVENANCE_MSG_TYPE:
            from one_link.provenance_wiring import handle_inbound_provenance
            handle_inbound_provenance(
                msg=msg,
                peer_fp=peer_fp,
                sender_public_bytes=self._peer_pubkey(peer_fp),
                store=self._provenance_store,
            )

    Malformed messages do not raise — they are logged and dropped.
    This matches the daemon's existing graceful-degradation posture
    for unknown / malformed wire types (wire.py:18).
    """
    try:
        parsed = parse_inbound_provenance_msg(msg)
    except ValueError as exc:
        log.warning("dropping malformed provenance from %s: %s", peer_fp[:8], exc)
        return None, False
    verified = verify_inbound(parsed, sender_public_bytes)
    store.record_inbound(
        blob_hex=parsed.blob_hex,
        peer_fp=peer_fp,
        provenance=parsed.provenance,
        verified=verified,
    )
    if not verified:
        log.warning(
            "provenance verification FAILED for blob=%s from peer=%s — recorded "
            "as unverified; UI will reflect this in Reality dot",
            parsed.blob_hex[:8],
            peer_fp[:8],
        )
    return parsed, verified
