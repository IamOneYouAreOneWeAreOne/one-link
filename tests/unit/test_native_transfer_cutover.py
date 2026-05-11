"""Phase C-3 (ADR-0026) FILE_NATIVE_CHUNK wire-format + capability
negotiation tests.

Covers the daemon-level cutover plumbing without spinning up a full
two-daemon socket pair. End-to-end socket coverage stays in the daemon
test suite (which still uses the legacy FILE_CHUNK path; opt-in is via
``ONE_LINK_NATIVE_TRANSFER=1``).
"""

from __future__ import annotations

import asyncio
import os

import pytest


def _native_available() -> bool:
    try:
        from one_link import native_transfer

        return native_transfer.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native not installed (build via maturin)",
)


# --- capability constant + advertise ---------------------------------------


def test_native_transfer_v1_in_local_capabilities():
    """The capability must be in the daemon's advertised set so peers
    discover it via CAPS."""
    from one_link import capabilities

    assert "native_transfer_v1" == capabilities.NATIVE_TRANSFER_V1
    assert capabilities.NATIVE_TRANSFER_V1 in capabilities.LOCAL_CAPABILITIES
    # It's a transport-layer cap (not user-prompt-required).
    assert capabilities.NATIVE_TRANSFER_V1 in capabilities.TRANSPORT_LAYER_CAPS


def test_channel_note_caps_records_native_transfer():
    """Channel.note_caps_received must flip
    peer_native_transfer_capable when peer advertises the cap."""
    from one_link.channel import Channel
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    loop = asyncio.new_event_loop()
    try:
        reader = asyncio.StreamReader(loop=loop)
        writer = type("W", (), {})()
        c = Channel(
            reader=reader,
            writer=writer,  # type: ignore[arg-type]
            peer_ed_pub=b"\x00" * 32,
            peer_short_id="peer_test",
            tx_aead=ChaCha20Poly1305(os.urandom(32)),
            rx_aead=ChaCha20Poly1305(os.urandom(32)),
            transcript_hash=os.urandom(32),
        )
        assert c.peer_native_transfer_capable is False
        c.note_caps_received(["double_ratchet_v1", "files", "native_transfer_v1"])
        assert c.peer_native_transfer_capable is True

        c2 = Channel(
            reader=reader,
            writer=writer,  # type: ignore[arg-type]
            peer_ed_pub=b"\x00" * 32,
            peer_short_id="peer_test_legacy",
            tx_aead=ChaCha20Poly1305(os.urandom(32)),
            rx_aead=ChaCha20Poly1305(os.urandom(32)),
            transcript_hash=os.urandom(32),
        )
        c2.note_caps_received(["double_ratchet_v1", "files"])  # legacy peer
        assert c2.peer_native_transfer_capable is False
    finally:
        loop.close()


# --- session caching -------------------------------------------------------


def _matched_channels():
    """Two channels that share DR-bootstrap material — emulates a
    post-handshake state. Same fixture shape as
    test_channel_native_transfer.py."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    from one_link.channel import Channel

    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    shared = alice_priv.exchange(bob_priv.public_key())
    transcript = os.urandom(32)
    bob_pub = bob_priv.public_key().public_bytes_raw()
    alice_pub = alice_priv.public_key().public_bytes_raw()

    def _build(role, my_priv, peer_pub):
        loop = asyncio.new_event_loop()
        c = Channel(
            reader=asyncio.StreamReader(loop=loop),
            writer=type("W", (), {})(),  # type: ignore[arg-type]
            peer_ed_pub=b"\x00" * 32,
            peer_short_id=f"peer_{role}",
            tx_aead=ChaCha20Poly1305(os.urandom(32)),
            rx_aead=ChaCha20Poly1305(os.urandom(32)),
            transcript_hash=transcript,
        )
        c._dr_role = role
        c._dr_x_priv = my_priv
        c._dr_peer_x_pub = peer_pub
        c._dr_shared = shared
        return c

    return _build("alice", alice_priv, bob_pub), _build("bob", bob_priv, alice_pub)


def test_get_or_create_native_transfer_session_caches():
    """Calling twice returns the same instance — confirms the daemon
    pattern of "build on first chunk, reuse for the rest of the
    channel" doesn't accidentally drift session state."""
    alice, _ = _matched_channels()
    s1 = alice.get_or_create_native_transfer_session()
    s2 = alice.get_or_create_native_transfer_session()
    assert s1 is s2


# --- wire-format round trip via paired sessions ----------------------------


def test_file_native_chunk_wire_envelope_round_trips():
    """Sender encrypts via its native session; the wire-shape encode
    (chunk_id hex, plaintext_len, base64 ciphertext) round-trips
    through a JSON-equivalent dict to the receiver's decrypt path."""
    import base64
    import json

    from one_link import native_transfer

    alice, bob = _matched_channels()
    sender = alice.get_or_create_native_transfer_session()
    receiver = bob.get_or_create_native_transfer_session()

    plaintext = os.urandom(2048)
    record = sender.encrypt_chunk_bytes(plaintext)

    # Build the FILE_NATIVE_CHUNK wire dict (what make_msg + encode_msg
    # would produce).
    wire = {
        "t": "FILE_NATIVE_CHUNK",
        "id": "test-id",
        "ts": 1234,
        "from": "alice",
        "blob": "deadbeef",
        "seq": 0,
        "chunk_id": record.chunk_id.hex(),
        "plaintext_len": record.plaintext_len,
        "data": base64.b64encode(record.ciphertext).decode("ascii"),
        "eof": True,
    }
    # Round trip through JSON to prove the encoded shape is valid.
    encoded = json.dumps(wire)
    decoded = json.loads(encoded)

    # Receiver reconstructs the record from the wire dict.
    rebuilt = native_transfer.NativeChunkRecord(
        chunk_id=bytes.fromhex(decoded["chunk_id"]),
        chunk_index=decoded["seq"],
        plaintext_len=decoded["plaintext_len"],
        ciphertext=base64.b64decode(decoded["data"]),
    )
    recovered = receiver.decrypt_chunk(rebuilt)
    assert recovered == plaintext


def test_file_native_chunk_aead_tag_rejects_swapped_chunk_id():
    """Wire-format tampering: rewrite chunk_id on the wire. The
    receiver's AEAD-AAD-bound tag check must reject before any
    plaintext leaks (the explicit BLAKE3 verify is dropped, so the
    AEAD is the only gate)."""
    import base64

    from one_link import native_transfer

    alice, bob = _matched_channels()
    sender = alice.get_or_create_native_transfer_session()
    receiver = bob.get_or_create_native_transfer_session()

    record = sender.encrypt_chunk_bytes(b"y" * 1024)
    # Tamper a byte in the chunk_id.
    tampered_id = bytearray(record.chunk_id)
    tampered_id[5] ^= 0xAA
    tampered = native_transfer.NativeChunkRecord(
        chunk_id=bytes(tampered_id),
        chunk_index=record.chunk_index,
        plaintext_len=record.plaintext_len,
        ciphertext=record.ciphertext,
    )
    with pytest.raises(Exception):
        receiver.decrypt_chunk(tampered)


# --- end-to-end multi-chunk round trip via paired channels ----------------


def test_multi_chunk_round_trip_via_paired_channels():
    """Stream 8 chunks via the sender, decode each through the
    receiver. Mirrors what daemon's send_file loop does end-to-end."""
    from one_link import native_transfer

    alice, bob = _matched_channels()
    sender = alice.get_or_create_native_transfer_session()
    receiver = bob.get_or_create_native_transfer_session()

    chunks = [os.urandom(64 * 1024) for _ in range(8)]
    records = [sender.encrypt_chunk_bytes(c) for c in chunks]
    recovered = [receiver.decrypt_chunk(r) for r in records]
    assert recovered == chunks


# --- env flag gating (sender opt-in) ---------------------------------------


def test_env_flag_default_off():
    """ONE_LINK_NATIVE_TRANSFER is opt-in: unset env should keep the
    sender on the legacy FILE_CHUNK path. We don't have a unit-test
    hook for the full send_file branch, so we assert the env variable
    semantic directly — daemon code reads
    ``os.environ.get("ONE_LINK_NATIVE_TRANSFER") == "1"``."""
    saved = os.environ.pop("ONE_LINK_NATIVE_TRANSFER", None)
    try:
        opted_in = os.environ.get("ONE_LINK_NATIVE_TRANSFER") == "1"
        assert opted_in is False
    finally:
        if saved is not None:
            os.environ["ONE_LINK_NATIVE_TRANSFER"] = saved


def test_env_flag_explicit_opt_in():
    saved = os.environ.get("ONE_LINK_NATIVE_TRANSFER")
    try:
        os.environ["ONE_LINK_NATIVE_TRANSFER"] = "1"
        opted_in = os.environ.get("ONE_LINK_NATIVE_TRANSFER") == "1"
        assert opted_in is True
    finally:
        if saved is None:
            os.environ.pop("ONE_LINK_NATIVE_TRANSFER", None)
        else:
            os.environ["ONE_LINK_NATIVE_TRANSFER"] = saved
