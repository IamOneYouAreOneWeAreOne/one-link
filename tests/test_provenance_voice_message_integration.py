"""Integration test: full FrameProvenance round-trip simulating the
voice-message v0.9.2 flow without spinning up two daemons.

This is the load-bearing acceptance test for Tier α-pre. It proves
that:

  1. A voice file recorded on Alice's device gets a signed
     FrameProvenance tag.
  2. Bob's daemon receives, parses, and verifies it against Alice's
     pinned master public key.
  3. Bob's ProvenanceStore holds the verified state, keyed by the
     same blob_hex the existing FILE_OFFER pipeline uses.
  4. The UI-facing state matches what the Reality dot will render.
  5. An attacker intercepting and re-signing fails verification.
  6. A malformed wire message is dropped without crashing.

The live daemon hooks are the ``FILE_PROVENANCE`` branch in
``_on_peer_message`` and the capability-gated send immediately after
``FILE_OFFER`` in ``send_file``. This test isolates the complete wire and
verification flow from sockets; the daemon dispatch and transfer tests cover
the two integration points themselves.
"""

from __future__ import annotations

import blake3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.capabilities import FRAME_PROVENANCE_V1, LOCAL_CAPABILITIES
from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
)
from one_link.identity import Identity
from one_link.provenance_wiring import (
    ProvenanceStore,
    build_provenance_for_file,
    handle_inbound_provenance,
    make_send_provenance_msg,
)
from one_link.wire import decode_msg, encode_msg


# ---------------------------------------------------------------------------
# Test doubles for "Alice" and "Bob" + a voice message
# ---------------------------------------------------------------------------

def _make_identity_named(name: str) -> Identity:
    """Build a deterministic Identity for clarity in test output."""
    seed_bytes = blake3.blake3(name.encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv,
        public=priv.public_key(),
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=name,
    )


@pytest.fixture
def alice() -> Identity:
    return _make_identity_named("alice")


@pytest.fixture
def bob() -> Identity:
    return _make_identity_named("bob")


@pytest.fixture
def mallory() -> Identity:
    return _make_identity_named("mallory")


@pytest.fixture
def voice_recording() -> bytes:
    """A plausibly-shaped opus blob (size + magic only; bytes are
    arbitrary for the cryptographic round-trip)."""
    return (
        b"\x1a\x45\xdf\xa3"   # Matroska/WebM magic
        + b"<opus voice frame 1>"
        + b"<opus voice frame 2>"
        + b"\x00" * 512
    )


@pytest.fixture
def voice_blob_hex(voice_recording: bytes) -> str:
    """Canonical BLAKE3-256 used by the daemon's ``FILE_OFFER.blob``."""
    return blake3.blake3(voice_recording).hexdigest()


# ---------------------------------------------------------------------------
# The full happy-path flow
# ---------------------------------------------------------------------------

def test_alice_sends_voice_message_bob_verifies_and_renders_reality_dot(
    alice: Identity,
    bob: Identity,
    voice_recording: bytes,
    voice_blob_hex: str,
) -> None:
    """End-to-end: Alice's voice message arrives at Bob with a
    verified Reality dot."""

    # ─── ALICE'S DEVICE ─────────────────────────────────────────────
    # User taps record, releases. Opus blob exists. Daemon's send-
    # file flow would normally compute size, blob_hex, build a
    # FILE_OFFER, and dispatch via channel.send. The live hook then sends
    # FILE_PROVENANCE on the same authenticated channel.

    alice_provenance = build_provenance_for_file(
        identity=alice,
        file_bytes=voice_recording,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        frame_kind=FrameKind.REAL,
        produce_confidence=1.0,
    )
    wire_msg = make_send_provenance_msg(
        sender_short_id=alice.short_id,
        blob_hex=voice_blob_hex,
        provenance=alice_provenance,
    )

    # The daemon would now ``await channel.send(encode_msg(wire_msg))``.
    # We simulate the channel as a byte buffer.
    on_wire_bytes = encode_msg(wire_msg)

    # ─── NETWORK IN BETWEEN ─────────────────────────────────────────
    # On real transport the bytes pass through DTLS-SRTP / QUIC /
    # ChaCha20-Poly1305. The provenance HMAC is independent of that
    # outer envelope — we test the inner end-to-end here.

    # ─── BOB'S DEVICE ───────────────────────────────────────────────
    # Bob's daemon recv loop decodes the frame and dispatches to the
    # FILE_PROVENANCE handler. The handler stores it in
    # ProvenanceStore so the UI can render the Reality dot.

    bob_store = ProvenanceStore()
    inbound_msg = decode_msg(on_wire_bytes)
    parsed, verified = handle_inbound_provenance(
        msg=inbound_msg,
        peer_fp=alice.fingerprint,
        sender_public_bytes=alice.public_bytes,
        store=bob_store,
    )

    # ─── ASSERTIONS ─────────────────────────────────────────────────

    # Wire parse + verify both succeeded.
    assert parsed is not None
    assert verified is True
    assert parsed.blob_hex == voice_blob_hex

    # Bob's store remembers what to render.
    entry = bob_store.get_inbound(voice_blob_hex)
    assert entry is not None
    assert entry.verified is True
    assert entry.peer_fp == alice.fingerprint

    # The UI dict is exactly what the Reality dot will receive.
    ui = bob_store.ui_state_for_blob(voice_blob_hex)
    assert ui == {
        "kind": "Original",
        "path": "Local network",
        "recording": "Not recording",
        "verified": True,
        "verification": "Sender signature confirmed",
        "scope": "Confirms the sender and exact bytes, not the truth of a physical scene",
        "produced_at_us": alice_provenance.timestamp_us,
    }

    # Doctrine §3.9.a — no hex / signatures leak.
    assert "seg" not in ui
    assert "sig" not in ui
    assert alice.fingerprint not in str(ui)


# ---------------------------------------------------------------------------
# Forgery scenario: Mallory tries to impersonate Alice
# ---------------------------------------------------------------------------

def test_mallory_cannot_impersonate_alice(
    alice: Identity,
    mallory: Identity,
    voice_recording: bytes,
    voice_blob_hex: str,
) -> None:
    """Mallory crafts a FILE_PROVENANCE claiming to be from Alice's
    device. Bob's pinned master_vk for Alice rejects it. The Reality
    dot reflects 'Unverified'."""

    fake = build_provenance_for_file(
        identity=mallory,
        file_bytes=voice_recording,
    )
    fake_msg = make_send_provenance_msg(
        sender_short_id=alice.short_id,  # spoofed
        blob_hex=voice_blob_hex,
        provenance=fake,
    )

    bob_store = ProvenanceStore()
    parsed, verified = handle_inbound_provenance(
        msg=fake_msg,
        peer_fp=alice.fingerprint,
        sender_public_bytes=alice.public_bytes,
        store=bob_store,
    )

    # Verification failed — but we still record the entry so the UI
    # can show "Unverified."
    assert parsed is not None
    assert verified is False
    entry = bob_store.get_inbound(voice_blob_hex)
    assert entry is not None
    assert entry.verified is False

    ui = bob_store.ui_state_for_blob(voice_blob_hex)
    assert ui is not None
    assert ui["verified"] is False


# ---------------------------------------------------------------------------
# Malformed messages don't crash the daemon path
# ---------------------------------------------------------------------------

def test_malformed_wire_message_dropped_silently(
    alice: Identity,
) -> None:
    """Bob's daemon never crashes on malformed peer input. The
    handler logs and drops; the store stays empty."""

    bob_store = ProvenanceStore()
    malformed_cases = [
        # Wrong type
        {"t": "TEXT"},
        # Missing blob
        {"t": "FILE_PROVENANCE", "from": "alice"},
        # Wrong-length blob hex
        {"t": "FILE_PROVENANCE", "from": "alice", "blob": "abc", "prov": {}},
        # Garbage prov dict
        {
            "t": "FILE_PROVENANCE",
            "from": "alice",
            "blob": "a" * 64,
            "prov": {"v": "not-an-int"},
        },
    ]
    for msg in malformed_cases:
        parsed, verified = handle_inbound_provenance(
            msg=msg,
            peer_fp=alice.fingerprint,
            sender_public_bytes=alice.public_bytes,
            store=bob_store,
        )
        assert parsed is None
        assert verified is False
    assert len(bob_store) == 0


# ---------------------------------------------------------------------------
# Capability declaration
# ---------------------------------------------------------------------------

def test_frame_provenance_capability_advertised() -> None:
    """The capability constant is exported and included in
    LOCAL_CAPABILITIES so peers learn we support provenance during
    CAPS handshake."""
    assert FRAME_PROVENANCE_V1 == "frame_provenance_v1"
    assert FRAME_PROVENANCE_V1 in LOCAL_CAPABILITIES


# ---------------------------------------------------------------------------
# Both sender + receiver path (record_outbound on Alice's own device)
# ---------------------------------------------------------------------------

def test_alice_records_her_own_outbound_provenance(
    alice: Identity,
    voice_recording: bytes,
    voice_blob_hex: str,
) -> None:
    """Alice's own device also remembers what it sent so its own UI
    can display the Reality dot on the outgoing message bubble."""
    alice_store = ProvenanceStore()
    p = build_provenance_for_file(identity=alice, file_bytes=voice_recording)
    alice_store.record_outbound(
        blob_hex=voice_blob_hex,
        peer_fp="bob-fp",
        provenance=p,
    )
    ui = alice_store.ui_state_for_blob(voice_blob_hex)
    assert ui is not None
    assert ui["verified"] is True   # we signed it, trivially verified
    assert ui["kind"] == "Original"
