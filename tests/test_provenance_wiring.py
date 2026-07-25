"""Tests for FrameProvenance wire integration.

Covers:
    - make_send_provenance_msg builds a valid wire envelope
    - parse_inbound_provenance_msg round-trips with the sender
    - verify_inbound passes for honest sender + fails for forgery
    - handle_inbound_provenance records inbound and reports verified
    - handle_inbound_provenance drops malformed messages without raising
    - ProvenanceStore round-trip (record_inbound, get_inbound, ui_state)
    - ProvenanceStore FIFO eviction at the configured cap
    - ProvenanceStore thread-safety under concurrent writes
    - Blob hex validation (rejects non-hex, wrong-length keys)
    - Wire round-trip through encode_msg / decode_msg of wire.py
"""

from __future__ import annotations

import threading

import blake3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
    make_segment_hash,
    to_wire_dict,
)
from one_link.identity import Identity
from one_link.provenance_wiring import (
    FRAME_PROVENANCE_CAP,
    PROVENANCE_MSG_TYPE,
    ProvenanceStore,
    build_provenance_for_hash,
    build_provenance_for_file,
    handle_inbound_provenance,
    make_send_provenance_msg,
    parse_inbound_provenance_msg,
    verify_inbound,
)
from one_link.wire import decode_msg, encode_msg


# ---------------------------------------------------------------------------
# Identity fixtures
# ---------------------------------------------------------------------------

def _make_identity() -> Identity:
    """Build an Identity without touching disk. Mirrors what
    identity.load_or_create returns but skips file persistence."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import blake3
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="test",
    )


@pytest.fixture
def sender_identity() -> Identity:
    return _make_identity()


@pytest.fixture
def receiver_identity() -> Identity:
    return _make_identity()


@pytest.fixture
def attacker_identity() -> Identity:
    return _make_identity()


@pytest.fixture
def voice_blob() -> bytes:
    return (
        b"\x1a\x45\xdf\xa3"   # EBML/Matroska header (looks like webm/opus)
        b"<opaque opus voice message bytes go here>"
        b"\x00" * 256
    )


@pytest.fixture
def voice_blob_hex(voice_blob: bytes) -> str:
    """The canonical BLAKE3-256 used by ``FILE_OFFER.blob``."""
    return blake3.blake3(voice_blob).hexdigest()


# ---------------------------------------------------------------------------
# Build + send-side
# ---------------------------------------------------------------------------

def test_build_provenance_for_file_signs_with_identity_key(
    sender_identity: Identity, voice_blob: bytes
) -> None:
    p = build_provenance_for_file(
        identity=sender_identity,
        file_bytes=voice_blob,
    )
    assert p.device_id == sender_identity.short_id
    assert p.segment_hash == make_segment_hash(voice_blob)
    assert p.frame_kind == FrameKind.REAL
    assert p.path_class == PathClass.LAN
    assert p.recording_state == RecordingState.NOT_RECORDING
    # Signature length is what an Ed25519 sign produces.
    assert len(p.signature) == 64


def test_build_provenance_for_hash_reuses_canonical_content_digest(
    sender_identity: Identity, voice_blob: bytes
) -> None:
    digest = blake3.blake3(voice_blob).digest()
    provenance = build_provenance_for_hash(
        identity=sender_identity,
        segment_hash=digest,
        path_class=PathClass.RELAY,
    )
    assert provenance.segment_hash == digest
    assert provenance.path_class == PathClass.RELAY


@pytest.mark.parametrize("digest", [b"", b"x" * 31, b"x" * 33])
def test_build_provenance_for_hash_rejects_non_blake3_lengths(
    sender_identity: Identity, digest: bytes
) -> None:
    with pytest.raises(ValueError, match="32-byte BLAKE3"):
        build_provenance_for_hash(
            identity=sender_identity,
            segment_hash=digest,
        )


def test_make_send_provenance_msg_envelope(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=sender_identity.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    assert msg["t"] == PROVENANCE_MSG_TYPE
    assert msg["from"] == sender_identity.short_id
    assert msg["blob"] == voice_blob_hex
    assert "ts" in msg
    assert "id" in msg
    assert msg["prov"] == to_wire_dict(p)


def test_make_send_provenance_msg_rejects_cross_blob_association(
    sender_identity: Identity, voice_blob: bytes
) -> None:
    provenance = build_provenance_for_file(
        identity=sender_identity,
        file_bytes=voice_blob,
    )
    with pytest.raises(ValueError, match="must match FILE_OFFER blob"):
        make_send_provenance_msg(
            sender_short_id=sender_identity.short_id,
            blob_hex=blake3.blake3(b"different file").hexdigest(),
            provenance=provenance,
        )


def test_send_provenance_msg_round_trips_through_wire_encoder(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    """The wire module's encode_msg / decode_msg pair is what the
    daemon actually uses to serialize. Our message must survive that
    round-trip byte-equal."""
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=sender_identity.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    blob = encode_msg(msg)
    decoded = decode_msg(blob)
    # Compare structurally (the JSON round-trip may reorder dict keys
    # but the content equates).
    assert decoded == msg


# ---------------------------------------------------------------------------
# Parse + verify (receive side)
# ---------------------------------------------------------------------------

def test_parse_inbound_provenance_msg_round_trip(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=sender_identity.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    parsed = parse_inbound_provenance_msg(msg)
    assert parsed.blob_hex == voice_blob_hex
    assert parsed.provenance == p


def test_parse_rejects_signed_provenance_replayed_for_another_blob(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    provenance = build_provenance_for_file(
        identity=sender_identity,
        file_bytes=voice_blob,
    )
    # Construct the outer envelope manually: the normal send helper refuses
    # this association before it can reach the wire.
    msg = {
        "t": PROVENANCE_MSG_TYPE,
        "id": "replay123",
        "ts": 1,
        "from": sender_identity.short_id,
        "blob": blake3.blake3(b"different file").hexdigest(),
        "prov": to_wire_dict(provenance),
    }
    assert msg["blob"] != voice_blob_hex
    with pytest.raises(ValueError, match="does not match offered blob"):
        parse_inbound_provenance_msg(msg)


def test_parse_rejects_wrong_message_type() -> None:
    msg = {"t": "TEXT", "id": "x", "ts": 0, "from": "abc"}
    with pytest.raises(ValueError, match="not a"):
        parse_inbound_provenance_msg(msg)


def test_parse_rejects_missing_blob() -> None:
    msg = {"t": PROVENANCE_MSG_TYPE, "id": "x", "ts": 0, "from": "abc"}
    with pytest.raises(ValueError, match="blob"):
        parse_inbound_provenance_msg(msg)


def test_parse_rejects_malformed_blob_hex() -> None:
    msg = {
        "t": PROVENANCE_MSG_TYPE,
        "id": "x", "ts": 0, "from": "abc",
        "blob": "not-hex-at-all",
        "prov": {},
    }
    with pytest.raises(ValueError, match="malformed"):
        parse_inbound_provenance_msg(msg)


def test_parse_rejects_short_blob_hex() -> None:
    msg = {
        "t": PROVENANCE_MSG_TYPE,
        "id": "x", "ts": 0, "from": "abc",
        "blob": "abc",
        "prov": {},
    }
    with pytest.raises(ValueError, match="malformed"):
        parse_inbound_provenance_msg(msg)


def test_parse_rejects_missing_prov_dict(
    voice_blob_hex: str,
) -> None:
    msg = {
        "t": PROVENANCE_MSG_TYPE,
        "id": "x", "ts": 0, "from": "abc",
        "blob": voice_blob_hex,
    }
    with pytest.raises(ValueError, match="prov"):
        parse_inbound_provenance_msg(msg)


def test_verify_inbound_passes_for_honest_sender(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=sender_identity.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    parsed = parse_inbound_provenance_msg(msg)
    assert verify_inbound(parsed, sender_identity.public_bytes) is True


def test_verify_inbound_fails_for_attacker(
    sender_identity: Identity,
    attacker_identity: Identity,
    voice_blob: bytes,
    voice_blob_hex: str,
) -> None:
    """An attacker signs a fake provenance claiming the sender's
    device_id. Receiver verifies against the sender's pinned key —
    must fail."""
    fake = build_provenance_for_file(
        identity=attacker_identity, file_bytes=voice_blob
    )
    # The attacker can't change the device_id without recomputing the
    # signature, but they might TRY to inject one with the sender's
    # short_id. We simulate that by passing the attacker-signed
    # provenance through the receiver-side verification keyed on the
    # claimed sender's public key.
    msg = make_send_provenance_msg(
        sender_short_id=attacker_identity.short_id,
        blob_hex=voice_blob_hex,
        provenance=fake,
    )
    parsed = parse_inbound_provenance_msg(msg)
    assert verify_inbound(parsed, sender_identity.public_bytes) is False


# ---------------------------------------------------------------------------
# End-to-end handler (the daemon calls this)
# ---------------------------------------------------------------------------

def test_handle_inbound_records_verified(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    store = ProvenanceStore()
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=sender_identity.short_id,
        blob_hex=voice_blob_hex,
        provenance=p,
    )
    parsed, verified = handle_inbound_provenance(
        msg=msg,
        peer_fp=sender_identity.fingerprint,
        sender_public_bytes=sender_identity.public_bytes,
        store=store,
    )
    assert parsed is not None
    assert verified is True
    # The store now holds it.
    entry = store.get_inbound(voice_blob_hex)
    assert entry is not None
    assert entry.verified is True
    assert entry.peer_fp == sender_identity.fingerprint


def test_handle_inbound_records_unverified_on_forgery(
    sender_identity: Identity,
    attacker_identity: Identity,
    voice_blob: bytes,
    voice_blob_hex: str,
) -> None:
    """When verification fails, the entry is still recorded — but as
    UNVERIFIED. The UI reflects this in the Reality dot ("Unverified
    sender"). We never drop verifiable signal silently."""
    store = ProvenanceStore()
    fake = build_provenance_for_file(identity=attacker_identity, file_bytes=voice_blob)
    msg = make_send_provenance_msg(
        sender_short_id=attacker_identity.short_id,
        blob_hex=voice_blob_hex,
        provenance=fake,
    )
    # Receiver verifies against the SENDER's pinned key, not the
    # attacker's — the path the daemon takes when peer_fp resolves to
    # the claimed sender.
    parsed, verified = handle_inbound_provenance(
        msg=msg,
        peer_fp=sender_identity.fingerprint,  # peer slot we think is sender
        sender_public_bytes=sender_identity.public_bytes,
        store=store,
    )
    assert parsed is not None
    assert verified is False
    entry = store.get_inbound(voice_blob_hex)
    assert entry is not None
    assert entry.verified is False


def test_handle_inbound_drops_malformed_silently(
    sender_identity: Identity, voice_blob_hex: str
) -> None:
    """Daemon's dispatch swallows malformed peer messages without
    crashing. Our handler must match that posture: log a warning,
    return (None, False)."""
    store = ProvenanceStore()
    malformed = {"t": PROVENANCE_MSG_TYPE, "from": "x"}  # missing blob, prov
    parsed, verified = handle_inbound_provenance(
        msg=malformed,
        peer_fp=sender_identity.fingerprint,
        sender_public_bytes=sender_identity.public_bytes,
        store=store,
    )
    assert parsed is None
    assert verified is False
    assert len(store) == 0


# ---------------------------------------------------------------------------
# ProvenanceStore
# ---------------------------------------------------------------------------

def test_store_inbound_outbound_separate(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    store = ProvenanceStore()
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)
    store.record_inbound(
        blob_hex=voice_blob_hex,
        peer_fp="peer-abc",
        provenance=p,
        verified=True,
    )
    store.record_outbound(
        blob_hex=voice_blob_hex,
        peer_fp="peer-abc",
        provenance=p,
    )
    assert store.get_inbound(voice_blob_hex) is not None
    assert store.get_outbound(voice_blob_hex) is not None


def test_store_ui_state_prefers_inbound(
    sender_identity: Identity, voice_blob: bytes, voice_blob_hex: str
) -> None:
    store = ProvenanceStore()
    inbound = build_provenance_for_file(
        identity=sender_identity,
        file_bytes=voice_blob,
        path_class=PathClass.LAN,
    )
    outbound = build_provenance_for_file(
        identity=sender_identity,
        file_bytes=voice_blob,
        path_class=PathClass.RELAY,
    )
    store.record_outbound(
        blob_hex=voice_blob_hex, peer_fp="x", provenance=outbound
    )
    store.record_inbound(
        blob_hex=voice_blob_hex, peer_fp="x", provenance=inbound, verified=True
    )
    ui = store.ui_state_for_blob(voice_blob_hex)
    assert ui is not None
    assert ui["path"] == "Local network"  # inbound's LAN, not outbound's relay


def test_store_ui_state_none_when_missing() -> None:
    store = ProvenanceStore()
    assert store.ui_state_for_blob("a" * 64) is None


def test_store_fifo_eviction_at_cap(
    sender_identity: Identity, voice_blob: bytes
) -> None:
    """Cap of 3 entries; insert 5 — first 2 are evicted."""
    store = ProvenanceStore(max_entries=3)
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)
    keys = [f"{i:064x}" for i in range(5)]
    for k in keys:
        store.record_inbound(
            blob_hex=k, peer_fp="x", provenance=p, verified=True
        )
    # First two evicted, last three retained.
    assert store.get_inbound(keys[0]) is None
    assert store.get_inbound(keys[1]) is None
    assert store.get_inbound(keys[2]) is not None
    assert store.get_inbound(keys[3]) is not None
    assert store.get_inbound(keys[4]) is not None


def test_store_thread_safe_under_concurrent_writes(
    sender_identity: Identity, voice_blob: bytes
) -> None:
    """Run 8 writer threads against a single store. We expect every
    write to land (no exceptions) and the final count to be bounded
    by the cap."""
    store = ProvenanceStore(max_entries=256)
    p = build_provenance_for_file(identity=sender_identity, file_bytes=voice_blob)

    errors: list[BaseException] = []

    def worker(start: int) -> None:
        try:
            for i in range(start, start + 50):
                store.record_inbound(
                    blob_hex=f"{i:064x}",
                    peer_fp="x",
                    provenance=p,
                    verified=True,
                )
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i * 50,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"thread errors: {errors}"
    # Total writes = 8 * 50 = 400; cap is 256.
    assert len(store) <= 256


def test_store_clear() -> None:
    store = ProvenanceStore()
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import blake3
    fp = blake3.blake3(pub_bytes).hexdigest()
    identity = Identity(
        private=priv,
        public=priv.public_key(),
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="test",
    )
    p = build_provenance_for_file(identity=identity, file_bytes=b"x")
    store.record_inbound(
        blob_hex="a" * 64, peer_fp="x", provenance=p, verified=True
    )
    assert len(store) == 1
    store.clear()
    assert len(store) == 0


# ---------------------------------------------------------------------------
# Capability constant
# ---------------------------------------------------------------------------

def test_capability_constant_value() -> None:
    """Match the capability-naming convention used by other v1
    capabilities (`*_v1` suffix, lowercase, snake_case)."""
    assert FRAME_PROVENANCE_CAP == "frame_provenance_v1"


def test_message_type_constant_value() -> None:
    assert PROVENANCE_MSG_TYPE == "FILE_PROVENANCE"
